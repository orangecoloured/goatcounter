// Copyright © 2019 Martin Tournoij <martin@arp242.net>
// This file is part of GoatCounter and published under the terms of the EUPL
// v1.2, which can be found in the LICENSE file or at http://eupl12.zgo.at

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"zgo.at/errors"
	"zgo.at/goatcounter"
	"zgo.at/goatcounter/cfg"
	"zgo.at/goatcounter/handlers"
	"zgo.at/goatcounter/logscan"
	"zgo.at/json"
	"zgo.at/zdb"
	"zgo.at/zhttp"
	"zgo.at/zli"
	"zgo.at/zlog"
	"zgo.at/zstd/zstring"
)

const usageImport = `
Import pageviews from an export or logfile.

Overview:

    You must give one filename to import; use - to read from stdin:

        $ goatcounter import export.csv.gz

    Or to read from a log file:

        $ goatcounter import -follow /var/log/nginx/access.log

    This requires a running GoatCounter instance; it's a front-end for the API
    rather than a tool to modify the database directly. If you add an ID or site
    code as the -site flag an API key can be generated automatically, but this
    requires access to the database.

    Alternatively, use an URL in -site if you want to send data to a remote
    instance:

        $ export GOATCOUNTER_API_KEY=..
        $ goatcounter import -site https://stats.example.com

Flags:

  -db          Database connection: "sqlite://<file>" or "postgres://<connect>"
               See "goatcounter help db" for detailed documentation. Default:
               sqlite://db/goatcounter.sqlite3?_busy_timeout=200&_journal_mode=wal&cache=shared

               Only needed if -site is not an URL.

  -debug       Modules to debug, comma-separated or 'all' for all modules.

  -silent      Don't show progress information.

  -site        Site to import to, can be passed as an ID ("1") or site code
               ("example") if you have access to the database. Can be omitted if there's only
               one site in the db.

               Use an URL ("https://stats.example.com") to send data to a remote
               instance; this requires setting GOATCOUNTER_API_KEY.

  -follow      Watch a file for new lines and import them. Existing lines are
               not processed.

  -format      Log format; currently accepted values:

                   csv             GoatCounter CSV export (default)
                   combined        NCSA Combined Log
                   combined-vhost  NCSA Combined Log with virtual host
                   common          Common Log Format (CLF)
                   common-vhost    Common Log Format (CLF) with virtual host
                   log:[fmt]       Custom log format; see "goatcounter help
                                   logfile" for details.

  -date, -time, -datetime
               Format of date and time for log imports; set automatically when
               using one of the predefined log formats and only needs to be set
               when using a custom log:[..]".
               This follows Go's time format; see "goatcounter help logfile" for
               an overview on how this works.

Environment:

  GOATCOUNTER_API_KEY   API key to use if you're connecting to a remote API;
                        must have "count" permission.
`

// w3c         W3C
// squid       Squid native log format
// aws-cf      AWS Amazon CloudFront (Download Distribution)
// aws-el      AWS Elastic Load Balancing
// aws-s3      AWS Amazon Simple Storage Service (S3)
// gcs         Google Cloud Storage
// virtualmin  Virtualmin Log Format with Virtual Host
// k8s-nginx   Kubernetes Nginx Ingress Log Format

const helpLogfile = `
Format specifiers are given as $name.

List of format specifiers:

    ignore         Ignore zero or more characters.

    time           Time according to the -time value.
    date           Date according to -date value.
    datetime       Date and time according to -datetime value.

    remote_addr    Client remote address; IPv4 or IPv6 address (DNS names are
                   not supported here).
    xff            Client remote address from X-Forwarded-For header field. The
                   remote address will be set to the last non-private IP
                   address.

    method         Request method.
    status         Status code sent to the client.
    http           HTTP request protocol (i.e. HTTP/1.1).
    path           URL path; this may contain the query string.
    query          Query string; only needed if not included in $path.
    referrer       "Referrer" request header.
    user_agent     User-Agent request header.

Some format specifiers that are not (yet) used anywhere:

    host           Server name of the server serving the request.
    timing_sec     Time to serve the request in seconds, with possible decimal.
    timing_milli   Time to serve the request in milliseconds.
    timing_micro   Time to serve the request in microseconds.
    size           Size of the object returned to the client.

Date and time parsing:

    Parsing the date and time is done with Go's time package; the following
    placeholders are recognized:

        2006           Year
        Jan            Month name
        1, 01          Month number
        2, 02          Day of month
        3, 03, 15      Hour
        4, 04          Minute
        5, 05          Seconds
        .000000000     Nanoseconds
        MST, -0700     Timezone

    You can give the following pre-defined values:

        ansic          Mon Jan _2 15:04:05 2006
        unix           Mon Jan _2 15:04:05 MST 2006
        rfc822         02 Jan 06 15:04 MST
        rfc822z        02 Jan 06 15:04 -0700
        rfc850         Monday, 02-Jan-06 15:04:05 MST
        rfc1123        Mon, 02 Jan 2006 15:04:05 MST
        rfc1123z       Mon, 02 Jan 2006 15:04:05 -0700
        rfc3339        2006-01-02T15:04:05Z07:00
        rfc3339nano    2006-01-02T15:04:05.999999999Z07:00

    The full documentation is available at https://pkg.go.dev/time
`

func importCmd() (int, error) {
	// So it uses https URLs in site.URL()
	// TODO: should fix it to always use https even on dev and get rid of the
	// exceptions.
	cfg.Prod = true

	dbConnect := flagDB()
	debug := flagDebug()

	var format, siteFlag, date, time, datetime string
	var silent, follow bool
	CommandLine.StringVar(&siteFlag, "site", "", "")
	CommandLine.StringVar(&format, "format", "csv", "")
	CommandLine.BoolVar(&silent, "silent", false, "")
	CommandLine.BoolVar(&follow, "follow", false, "")
	CommandLine.StringVar(&date, "date", "", "")
	CommandLine.StringVar(&time, "time", "", "")
	CommandLine.StringVar(&datetime, "datetime", "", "")
	err := CommandLine.Parse(os.Args[2:])
	if err != nil {
		return 1, err
	}

	files := CommandLine.Args()
	if len(files) == 0 {
		return 1, fmt.Errorf("need a filename")
	}
	if len(files) > 1 {
		return 1, fmt.Errorf("can only specify one filename")
	}

	var fp io.ReadCloser
	if files[0] == "-" {
		fp = ioutil.NopCloser(os.Stdin)
	} else {
		file, err := os.Open(files[0])
		if err != nil {
			return 1, err
		}
		defer file.Close()

		if strings.HasSuffix(files[0], ".gz") {
			fp, err = gzip.NewReader(file)
			if err != nil {
				return 1, errors.Errorf("could not read as gzip: %w", err)
			}
		} else {
			fp = file
		}
		defer fp.Close()
	}

	zlog.Config.SetDebug(*debug)

	url, key, clean, err := findSite(siteFlag, *dbConnect)
	if err != nil {
		return 1, err
	}
	if clean != nil {
		defer clean()
	}

	err = checkSite(url, key)
	if err != nil {
		return 1, err
	}

	url += "/api/v0/count"

	// Import from CSV.
	if format == "csv" {
		if follow {
			return 1, fmt.Errorf("cannot use -follow with -format=csv")
		}

		n := 0
		ctx := goatcounter.WithSite(context.Background(), &goatcounter.Site{})
		hits := make([]handlers.APICountRequestHit, 0, 500)
		_, err = goatcounter.Import(ctx, fp, false, false, func(hit goatcounter.Hit, final bool) {
			if !final {
				hits = append(hits, handlers.APICountRequestHit{
					Path:      hit.Path,
					Title:     hit.Title,
					Event:     hit.Event,
					Ref:       hit.Ref,
					Size:      hit.Size,
					Bot:       hit.Bot,
					UserAgent: hit.UserAgentHeader,
					Location:  hit.Location,
					CreatedAt: hit.CreatedAt,
					Session:   hit.Session.String(),
				})
			}

			if len(hits) >= 500 || final {
				err := importSend(url, key, silent, hits)
				if err != nil {
					fmt.Println()
					zli.Errorf(err)
				}

				n += len(hits)
				if !silent {
					zli.ReplaceLinef("Imported %d rows", n)
				}

				hits = make([]handlers.APICountRequestHit, 0, 500)
			}
		})
		if err != nil {
			return 1, err
		}

		return 0, nil
	}

	// Assume log file for everything else.
	var scan *logscan.Scanner
	if follow && files[0] != "-" {
		fp.Close()
		scan, err = logscan.NewFollow(files[0], format, date, time, datetime)
	} else {
		scan, err = logscan.New(fp, format, date, time, datetime)
	}
	if err != nil {
		return 1, err
	}

	hits := make([]handlers.APICountRequestHit, 0, 100)
	for {
		line, err := scan.Line()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 1, err
		}

		hit := handlers.APICountRequestHit{
			Path:      line.Path(),
			Ref:       line.Referrer(),
			Query:     line.Query(),
			UserAgent: line.UserAgent(),
		}

		hit.CreatedAt, err = line.Datetime(scan)
		if err != nil {
			zlog.Error(err)
			continue
		}

		if line.XForwardedFor() != "" {
			xffSplit := strings.Split(line.XForwardedFor(), ",")
			for i := len(xffSplit) - 1; i >= 0; i-- {
				if !zhttp.PrivateIP(xffSplit[i]) {
					hit.IP = zhttp.RemovePort(strings.TrimSpace(xffSplit[i]))
					break
				}
			}
		}
		if hit.IP == "" {
			hit.IP = zhttp.RemovePort(line.RemoteAddr())
		}

		hits = append(hits, hit)

		if len(hits) == 100 {
			// TODO: limit goroutines here
			go func(hits []handlers.APICountRequestHit) {
				defer zlog.Recover()

				err := importSend(url, key, silent, hits)
				if err != nil {
					zlog.Error(err)
				}
			}(hits)

			hits = make([]handlers.APICountRequestHit, 0, 100)
		}
	}

	if len(hits) > 0 {
		err := importSend(url, key, silent, hits)
		if err != nil {
			zlog.Error(err)
		}
	}

	return 0, nil
}

var (
	importClient = http.Client{Timeout: 5 * time.Second}
	nSent        int
)

func newRequest(method, url, key string, body io.Reader) (*http.Request, error) {
	r, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key)
	return r, nil
}

func importSend(url, key string, silent bool, hits []handlers.APICountRequestHit) error {
	body, err := json.Marshal(handlers.APICountRequest{Hits: hits})
	if err != nil {
		return err
	}

	r, err := newRequest("POST", url, key, bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set("X-Goatcounter-Import", "yes")

	resp, err := importClient.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 202: // All okay!
	case 429: // Rate limit
		s, err := strconv.Atoi(resp.Header.Get("X-Rate-Limit-Reset"))
		if err != nil {
			return err
		}

		time.Sleep(time.Duration(s) * time.Second)

	// Other error
	default:
		b, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s: %s", url, resp.Status, zstring.ElideLeft(string(b), 200))
	}

	nSent += len(hits)

	// Give the server's memstore a second to do its job.
	if nSent > 5000 {
		time.Sleep(1 * time.Second)
		nSent = 0
	}
	return nil
}

func findSite(siteFlag, dbConnect string) (string, string, func(), error) {
	var (
		url, key string
		clean    func()
	)
	switch {
	case strings.HasPrefix(siteFlag, "http://") || strings.HasPrefix(siteFlag, "https://"):
		url = strings.TrimRight(siteFlag, "/")
		url = strings.TrimSuffix(url, "/api/v0/count")
		if !strings.HasPrefix(url, "http") {
			url = "https://" + url
		}

		key = os.Getenv("GOATCOUNTER_API_KEY")
		if key == "" {
			return "", "", nil, errors.New("GOATCOUNTER_API_KEY must be set")
		}

	default:
		db, err := connectDB(dbConnect, nil, false)
		if err != nil {
			return "", "", nil, err
		}
		defer db.Close()
		ctx := zdb.With(context.Background(), db)

		var site goatcounter.Site
		siteID, intErr := strconv.ParseInt(siteFlag, 10, 64)
		switch {
		default:
			err = site.ByCode(ctx, siteFlag)
		case intErr == nil && siteID > 0:
			err = site.ByID(ctx, siteID)
		case siteFlag == "":
			var sites goatcounter.Sites
			err := sites.UnscopedList(ctx)
			if err != nil {
				return "", "", nil, err
			}

			switch len(sites) {
			case 0:
				return "", "", nil, fmt.Errorf("there are no sites in the database")
			case 1:
				site = sites[0]
			default:
				return "", "", nil, fmt.Errorf("more than one site: use -site to specify which site to import")
			}
		}
		if err != nil {
			return "", "", nil, err
		}
		ctx = goatcounter.WithSite(ctx, &site)

		var user goatcounter.User
		err = user.BySite(ctx, site.ID)
		if err != nil {
			return "", "", nil, err
		}
		ctx = goatcounter.WithUser(ctx, &user)

		token := goatcounter.APIToken{
			SiteID:      site.ID,
			Name:        "goatcounter import",
			Permissions: goatcounter.APITokenPermissions{Count: true},
		}
		err = token.Insert(ctx)
		if err != nil {
			return "", "", nil, err
		}

		url = site.URL()
		key = token.Token
		clean = func() { token.Delete(ctx) }
	}

	return url, key, clean, nil
}

// Verify that the site is live and that we've got the correct permissions.
func checkSite(url, key string) error {
	r, err := newRequest("GET", url+"/api/v0/me", key, nil)
	if err != nil {
		return err
	}

	resp, err := importClient.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: %s: %s", url+"/api/v0/me",
			resp.Status, zstring.ElideLeft(string(b), 200))
	}

	var perm struct {
		Token goatcounter.APIToken `json:"token"`
	}
	err = json.Unmarshal(b, &perm)
	if err != nil {
		return err
	}
	if !perm.Token.Permissions.Count {
		return fmt.Errorf("the API token %q is missing the 'count' permission", perm.Token.Name)
	}

	return nil
}
