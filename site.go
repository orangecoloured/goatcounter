// Copyright © 2019 Martin Tournoij – This file is part of GoatCounter and
// published under the terms of a slightly modified EUPL v1.2 license, which can
// be found in the LICENSE file or at https://license.goatcounter.com

package goatcounter

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"zgo.at/errors"
	"zgo.at/goatcounter/cfg"
	"zgo.at/guru"
	"zgo.at/tz"
	"zgo.at/zcache"
	"zgo.at/zdb"
	"zgo.at/zhttp"
	"zgo.at/zlog"
	"zgo.at/zstd/zint"
	"zgo.at/zvalidate"
)

// Plan column values.
const (
	PlanPersonal     = "personal"
	PlanPersonalPlus = "personalplus" // This is really the "starter" plan.
	PlanBusiness     = "business"
	PlanBusinessPlus = "businessplus"
	PlanChild        = "child"
)

var Plans = []string{PlanPersonal, PlanPersonalPlus, PlanBusiness, PlanBusinessPlus}

var reserved = []string{
	"www", "mail", "smtp", "imap", "static",
	"admin", "ns1", "ns2", "m", "mobile", "api",
	"dev", "test", "beta", "new", "staging", "debug", "pprof",
	"chat", "example", "yoursite", "test", "sql", "license",
}

var statTables = []string{"hit_stats", "system_stats", "browser_stats",
	"location_stats", "size_stats"}

type Site struct {
	ID     int64  `db:"site_id" json:"id,readonly"`
	Parent *int64 `db:"parent" json:"parent,readonly"`

	// Custom domain, e.g. "stats.example.com"
	Cname *string `db:"cname" json:"cname"`

	// When the CNAME was verified.
	CnameSetupAt *time.Time `db:"cname_setup_at" json:"cname_setup_at,readonly"`

	// Domain code (arp242, which makes arp242.goatcounter.com)
	Code string `db:"code" json:"code"`

	// Site domain for linking (www.arp242.net).
	LinkDomain    string       `db:"link_domain" json:"link_domain"`
	Plan          string       `db:"plan" json:"plan"`
	Stripe        *string      `db:"stripe" json:"-"`
	BillingAmount *string      `db:"billing_amount" json:"-"`
	Settings      SiteSettings `db:"settings" json:"setttings"`

	// Whether this site has received any data; will be true after the first
	// pageview.
	ReceivedData bool `db:"received_data" json:"received_data"`

	State      string     `db:"state" json:"state"`
	CreatedAt  time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt  *time.Time `db:"updated_at" json:"updated_at"`
	FirstHitAt time.Time  `db:"first_hit_at" json:"first_hit_at"`
}

var (
	sitesCacheByID     = zcache.New(24*time.Hour, 1*time.Hour)
	sitesCacheHostname = zcache.New(24*time.Hour, 1*time.Hour)
)

// ClearCache clears the  cache for this site.
func (s Site) ClearCache(full bool) {
	sitesCacheByID.Delete(strconv.FormatInt(s.ID, 10))

	// TODO: be more selective about this.
	if full {
		cachePaths.Flush()
		changedTitles.Flush()
	}
}

// Defaults sets fields to default values, unless they're already set.
func (s *Site) Defaults(ctx context.Context) {
	// New site: Set default settings.
	if s.ID == 0 {
		s.Settings.Campaigns = []string{"utm_campaign", "utm_source", "ref"}
	}

	if s.State == "" {
		s.State = StateActive
	}

	if s.Settings.DateFormat == "" {
		s.Settings.DateFormat = "2 Jan ’06"
	}
	if s.Settings.NumberFormat == 0 {
		s.Settings.NumberFormat = 0x202f
	}
	if s.Settings.Timezone == nil {
		s.Settings.Timezone = tz.UTC
	}

	if len(s.Settings.Widgets) == 0 {
		s.Settings.Widgets = defaultWidgets()
	}

	if len(s.Settings.Views) == 0 {
		s.Settings.Views = Views{{Name: "default", Period: "week"}}
	}

	s.Code = strings.ToLower(s.Code)

	if s.CreatedAt.IsZero() {
		s.CreatedAt = Now()
	} else {
		t := Now()
		s.UpdatedAt = &t
	}
	if s.FirstHitAt.IsZero() {
		s.FirstHitAt = Now()
	}
}

var noUnderscore = time.Date(2020, 03, 20, 0, 0, 0, 0, time.UTC)

// Validate the object.
func (s *Site) Validate(ctx context.Context) error {
	v := zvalidate.New()

	v.Required("code", s.Code)
	v.Required("state", s.State)
	v.Required("plan", s.Plan)
	v.Include("state", s.State, States)
	if s.Parent == nil {
		v.Include("plan", s.Plan, Plans)
	} else {
		v.Include("plan", s.Plan, []string{PlanChild})
	}

	// Must always include all widgets we know about.
	for _, w := range defaultWidgets() {
		if s.Settings.Widgets.Get(w["name"].(string)) == nil {
			v.Append("widgets", fmt.Sprintf("widget %q is missing", w["name"].(string)))
		}
	}
	v.Range("widgets.pages.s.limit_pages", int64(s.Settings.LimitPages()), 1, 100)
	v.Range("widgets.pages.s.limit_refs", int64(s.Settings.LimitRefs()), 1, 25)

	if _, i := s.Settings.Views.Get("default"); i == -1 || len(s.Settings.Views) != 1 {
		v.Append("views", "view not set")
	}

	if s.Settings.DataRetention > 0 {
		v.Range("settings.data_retention", int64(s.Settings.DataRetention), 14, 0)
	}

	if len(s.Settings.IgnoreIPs) > 0 {
		for _, ip := range s.Settings.IgnoreIPs {
			v.IP("settings.ignore_ips", ip)
		}
	}

	v.Domain("link_domain", s.LinkDomain)
	v.Len("code", s.Code, 2, 50)
	v.Exclude("code", s.Code, reserved)
	// TODO: compat with older requirements, otherwise various update functions
	// will error out.
	if !s.CreatedAt.IsZero() && s.CreatedAt.Before(noUnderscore) {
		for _, c := range s.Code {
			if !(c == '-' || c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
				v.Append("code", fmt.Sprintf("%q not allowed; characters are limited to '_', '-', a to z, and numbers", c))
				break
			}
		}
		if len(s.Code) > 0 && (s.Code[0] == '_' || s.Code[0] == '-') { // Special domains, like _acme-challenge.
			v.Append("code", "cannot start with underscore or dash (_, -)")
		}
	} else {
		labels := v.Hostname("code", s.Code)
		if len(labels) > 1 {
			v.Append("code", "cannot contain '.'")
		}
	}

	if s.Cname != nil {
		v.Len("cname", *s.Cname, 4, 255)
		v.Domain("cname", *s.Cname)
		if cfg.GoatcounterCom && strings.HasSuffix(*s.Cname, cfg.Domain) {
			v.Append("cname", "cannot end with %q", cfg.Domain)
		}

		var cname uint8
		err := zdb.MustGet(ctx).GetContext(ctx, &cname,
			`select 1 from sites where lower(cname)=lower($1) and site_id!=$2 limit 1`,
			s.Cname, s.ID)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if cname == 1 {
			v.Append("cname", "already exists")
		}
	}

	if s.Stripe != nil && !strings.HasPrefix(*s.Stripe, "cus_") {
		v.Append("stripe", "not a valid Stripe customer ID")
	}

	if !v.HasErrors() {
		var code uint8
		err := zdb.MustGet(ctx).GetContext(ctx, &code,
			`select 1 from sites where lower(code)=lower($1) and site_id!=$2 limit 1`,
			s.Code, s.ID)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if code == 1 {
			v.Append("code", "already exists")
		}
	}

	return v.ErrorOrNil()
}

// Insert a new row.
func (s *Site) Insert(ctx context.Context) error {
	if s.ID > 0 {
		return errors.New("ID > 0")
	}

	s.Defaults(ctx)
	err := s.Validate(ctx)
	if err != nil {
		return err
	}

	s.ID, err = zdb.InsertID(ctx, "site_id", `insert into sites
		(parent, code, cname, link_domain, settings, plan, created_at, first_hit_at)
		values ($1, $2, $3, $4, $5, $6, $7, $8)`,
		s.Parent, s.Code, s.Cname, s.LinkDomain, s.Settings, s.Plan,
		s.CreatedAt.Format(zdb.Date), s.CreatedAt.Format(zdb.Date))
	if err != nil && zdb.ErrUnique(err) {
		return guru.New(400, "this site already exists: code or domain must be unique")
	}
	return errors.Wrap(err, "Site.Insert")
}

// Update existing.
func (s *Site) Update(ctx context.Context) error {
	if s.ID == 0 {
		return errors.New("ID == 0")
	}

	s.Defaults(ctx)
	err := s.Validate(ctx)
	if err != nil {
		return err
	}

	_, err = zdb.MustGet(ctx).ExecContext(ctx,
		`update sites set settings=$1, cname=$2, link_domain=$3, updated_at=$4 where site_id=$5`,
		s.Settings, s.Cname, s.LinkDomain, s.UpdatedAt.Format(zdb.Date), s.ID)
	if err != nil {
		return errors.Wrap(err, "Site.Update")
	}

	s.ClearCache(false)
	return nil
}

// UpdateStripe sets the Stripe customer ID.
func (s *Site) UpdateStripe(ctx context.Context, stripeID, plan, amount string) error {
	if s.ID == 0 {
		return errors.New("ID == 0")
	}

	s.Defaults(ctx)
	err := s.Validate(ctx)
	if err != nil {
		return err
	}

	s.Stripe = &stripeID
	s.Plan = plan
	if amount == "" {
		s.BillingAmount = nil
	} else {
		s.BillingAmount = &amount
	}

	_, err = zdb.MustGet(ctx).ExecContext(ctx,
		`update sites set stripe=$1, plan=$2, billing_amount=$3, updated_at=$4 where site_id=$5`,
		s.Stripe, s.Plan, s.BillingAmount, s.UpdatedAt.Format(zdb.Date), s.ID)
	if err != nil {
		return errors.Wrap(err, "Site.UpdateStripe")
	}

	s.ClearCache(false)
	return nil
}

// UpdateCode changes the site's domain code (e.g. "test" in
// "test.goatcounter.com").
func (s *Site) UpdateCode(ctx context.Context, code string) error {
	if s.ID == 0 {
		return errors.New("ID == 0")
	}

	s.Code = code

	s.Defaults(ctx)
	err := s.Validate(ctx)
	if err != nil {
		return err
	}

	_, err = zdb.MustGet(ctx).ExecContext(ctx,
		`update sites set code=$1, updated_at=$2 where site_id=$3`,
		s.Code, s.UpdatedAt.Format(zdb.Date), s.ID)
	if err != nil {
		return errors.Wrap(err, "Site.UpdateCode")
	}

	sitesCacheByID.Delete(strconv.FormatInt(s.ID, 10))
	return nil
}

func (s *Site) UpdateReceivedData(ctx context.Context) error {
	_, err := zdb.MustGet(ctx).ExecContext(ctx,
		`update sites set received_data=1 where site_id=$1`, s.ID)

	s.ClearCache(false)
	return errors.Wrap(err, "Site.UpdateReceivedData")
}

func (s *Site) UpdateFirstHitAt(ctx context.Context, f time.Time) error {
	s.FirstHitAt = f
	_, err := zdb.MustGet(ctx).ExecContext(ctx,
		`update sites set first_hit_at=$1 where site_id=$2`,
		s.FirstHitAt.Format(zdb.Date), s.ID)

	s.ClearCache(false)
	return errors.Wrap(err, "Site.UpdateFirstHitAt")
}

// UpdateCnameSetupAt confirms the custom domain was setup correct.
func (s *Site) UpdateCnameSetupAt(ctx context.Context) error {
	if s.ID == 0 {
		return errors.New("ID == 0")
	}

	n := Now()
	s.CnameSetupAt = &n

	_, err := zdb.MustGet(ctx).ExecContext(ctx,
		`update sites set cname_setup_at=$1 where site_id=$2`,
		s.CnameSetupAt.Format(zdb.Date), s.ID)
	if err != nil {
		return errors.Wrap(err, "Site.UpdateCnameSetupAt")
	}

	s.ClearCache(false)
	return nil
}

// Delete a site.
func (s *Site) Delete(ctx context.Context) error {
	if s.ID == 0 {
		return errors.New("ID == 0")
	}

	t := Now()
	_, err := zdb.MustGet(ctx).ExecContext(ctx,
		`update sites set state=$1, updated_at=$2 where site_id=$3 or parent=$3`,
		StateDeleted, t.Format(zdb.Date), s.ID)
	if err != nil {
		return errors.Wrap(err, "Site.Delete")
	}

	s.ClearCache(true)

	s.ID = 0
	s.UpdatedAt = &t
	s.State = StateDeleted
	return nil
}

// ByID gets a site by ID.
func (s *Site) ByID(ctx context.Context, id int64) error {
	k := strconv.FormatInt(id, 10)
	ss, ok := sitesCacheByID.Get(k)
	if ok {
		*s = *ss.(*Site)
		return nil
	}

	err := zdb.MustGet(ctx).GetContext(ctx, s,
		`/* Site.ByID */ select * from sites where site_id=$1 and state=$2`,
		id, StateActive)
	if err != nil {
		return errors.Wrapf(err, "Site.ByID %d", id)
	}
	sitesCacheByID.SetDefault(k, s)
	return nil
}

// ByCode gets a site by code.
func (s *Site) ByCode(ctx context.Context, code string) error {
	return errors.Wrapf(zdb.MustGet(ctx).GetContext(ctx, s,
		`/* Site.ByCode */ select * from sites where code=$1 and state=$2`,
		code, StateActive), "Site.ByCode %s", code)
}

// ByHost gets a site by host name.
func (s *Site) ByHost(ctx context.Context, host string) error {
	id, ok := sitesCacheHostname.Get(host)
	if ok {
		return s.ByID(ctx, id.(int64))
	}

	// Custom domain or serve.
	if cfg.Serve || !strings.HasSuffix(host, cfg.Domain) {
		err := zdb.MustGet(ctx).GetContext(ctx, s,
			`/* Site.ByHost */ select * from sites where lower(cname)=lower($1) and state=$2`,
			zhttp.RemovePort(host), StateActive)
		if err != nil {
			return errors.Wrap(err, "site.ByHost: from custom domain")
		}
		sitesCacheHostname.SetDefault(host, s.ID)
		return nil
	}

	// Get from code (e.g. "arp242" in "arp242.goatcounter.com").
	p := strings.Index(host, ".")
	if p == -1 {
		return errors.Errorf("Site.ByHost: no subdomain in host %q", host)
	}

	err := zdb.MustGet(ctx).GetContext(ctx, s,
		`/* Site.ByHost */ select * from sites where lower(code)=lower($1) and state=$2`,
		host[:p], StateActive)
	if err != nil {
		return errors.Wrap(err, "site.ByHost: from code")
	}
	sitesCacheHostname.SetDefault(host, s.ID)
	return nil
}

// ListSubs lists all subsites, including the current site and parent.
func (s *Site) ListSubs(ctx context.Context) ([]string, error) {
	col := "code"
	if cfg.Serve {
		col = "cname"
	}
	var codes []string
	err := zdb.MustGet(ctx).SelectContext(ctx, &codes, `/* Site.ListSubs */
		select `+col+` from sites
		where state=$1 and (parent=$2 or site_id=$2) or (
			parent  = (select parent from sites where site_id=$2) or
			site_id = (select parent from sites where site_id=$2)
		) and state=$1
		order by code
		`, StateActive, s.ID)
	return codes, errors.Wrap(err, "Site.ListSubs")
}

// Domain gets the global default domain, or this site's configured custom
// domain.
func (s Site) Domain() string {
	if s.Cname != nil && s.CnameSetupAt != nil {
		return *s.Cname
	}
	return cfg.Domain
}

// Display format: just the domain (cname or code+domain).
//
//lint:ignore U1001 used in template.
func (s Site) Display() string {
	if s.Cname != nil && s.CnameSetupAt != nil {
		return *s.Cname
	}
	return fmt.Sprintf("%s.%s", s.Code, zhttp.RemovePort(cfg.Domain))
}

// URL to this site.
func (s Site) URL() string {
	if s.Cname != nil && s.CnameSetupAt != nil {
		return fmt.Sprintf("http%s://%s%s",
			map[bool]string{true: "s", false: ""}[cfg.Prod],
			*s.Cname, cfg.Port)
	}

	return fmt.Sprintf("http%s://%s.%s%s",
		map[bool]string{true: "s", false: ""}[cfg.Prod],
		s.Code, cfg.Domain, cfg.Port)
}

// PlanCustomDomain reports if this site's plan allows custom domains.
func (s Site) PlanCustomDomain(ctx context.Context) bool {
	if s.Parent != nil {
		var ps Site
		err := ps.ByID(ctx, *s.Parent)
		if err != nil {
			zlog.Error(err)
			return false
		}
		return ps.PlanCustomDomain(ctx)
	}

	return s.Plan == PlanPersonalPlus || s.Plan == PlanBusiness || s.Plan == PlanBusinessPlus
}

// IDOrParent gets this site's ID or the parent ID if that's set.
func (s Site) IDOrParent() int64 {
	if s.Parent != nil {
		return *s.Parent
	}
	return s.ID
}

//lint:ignore U1001 used in template (via ShowPayBanner)
var trialPeriod = time.Hour * 24 * 14

// ShowPayBanner determines if we should show a "please pay" banner for the
// customer.
//
//lint:ignore U1001 used in template.
func (s Site) ShowPayBanner(ctx context.Context) bool {
	if s.Parent != nil {
		var ps Site
		err := ps.ByID(ctx, *s.Parent)
		if err != nil {
			zlog.Error(err)
			return false
		}
		return ps.ShowPayBanner(ctx)
	}

	if s.Stripe != nil {
		return false
	}
	return -Now().Sub(s.CreatedAt.Add(trialPeriod)) < 0
}

func (s Site) FreePlan() bool {
	return s.Stripe != nil && strings.HasPrefix(*s.Stripe, "cus_free_")
}

func (s Site) PayExternal() string {
	if s.Stripe == nil {
		return ""
	}

	if strings.HasPrefix(*s.Stripe, "cus_github_") {
		return "GitHub Sponsors"
	}
	if strings.HasPrefix(*s.Stripe, "cus_patreon_") {
		return "Patreon"
	}
	return ""
}

// DeleteAll deletes all pageviews for this site, keeping the site itself and
// user intact.
func (s Site) DeleteAll(ctx context.Context) error {
	return zdb.TX(ctx, func(ctx context.Context, tx zdb.DB) error {
		for _, t := range append(statTables, "hit_counts", "ref_counts", "hits", "paths") {
			_, err := tx.ExecContext(ctx, `delete from `+t+` where site_id=$1`, s.ID)
			if err != nil {
				return errors.Wrap(err, "Site.DeleteAll: delete "+t)
			}
		}

		s.ClearCache(true)
		return nil
	})
}

func (s Site) DeleteOlderThan(ctx context.Context, days int) error {
	if days < 14 {
		return errors.Errorf("days must be at least 14: %d", days)
	}

	return zdb.TX(ctx, func(ctx context.Context, tx zdb.DB) error {
		ival := interval(ctx, days)

		var pathIDs []int64
		err := tx.SelectContext(ctx, &pathIDs, `/* Site.DeleteOlderThan */
			select path_id from hit_counts where site_id=$1 and hour < `+ival+` group by path_id`, s.ID)
		if err != nil {
			return errors.Wrap(err, "Site.DeleteOlderThan: get paths")
		}

		for _, t := range statTables {
			_, err := tx.ExecContext(ctx, `delete from `+t+` where site_id=$1 and day < `+ival, s.ID)
			if err != nil {
				return errors.Wrap(err, "Site.DeleteOlderThan: delete "+t)
			}
		}

		_, err = tx.ExecContext(ctx, `delete from hit_counts where site_id=$1 and hour < `+ival, s.ID)
		if err != nil {
			return errors.Wrap(err, "Site.DeleteOlderThan: delete hit_counts")
		}
		_, err = tx.ExecContext(ctx, `delete from ref_counts where site_id=$1 and hour < `+ival, s.ID)
		if err != nil {
			return errors.Wrap(err, "Site.DeleteOlderThan: delete ref_counts")
		}

		_, err = tx.ExecContext(ctx, `delete from hits where site_id=$1 and created_at < `+ival, s.ID)
		if err != nil {
			return errors.Wrap(err, "Site.DeleteOlderThan: delete hits")
		}

		if len(pathIDs) > 0 {
			db := zdb.MustGet(ctx)
			query, args, err := sqlx.In(`/* Site.DeleteOlderThan */
				select path_id from hit_counts where site_id=? and path_id in (?)`,
				s.ID, pathIDs)
			if err != nil {
				return errors.Wrap(err, "Site.DeleteOlderThan")
			}
			var remainPath []int64
			err = tx.SelectContext(ctx, &remainPath, db.Rebind(query), args...)
			if err != nil {
				return errors.Wrap(err, "Site.DeleteOlderThan")
			}

			diff := zint.Difference(pathIDs, remainPath)
			if len(diff) > 0 {
				query, args, err := sqlx.In(`delete from paths where site_id=? and path_id in (?)`, s.ID, diff)
				if err != nil {
					return errors.Wrap(err, "Site.DeleteOlderThan")
				}
				_, err = tx.ExecContext(ctx, db.Rebind(query), args...)
				if err != nil {
					return errors.Wrap(err, "Site.DeleteOlderThan")
				}
			}
		}

		return nil
	})
}

// Admin reports if this site is an admin.
func (s Site) Admin() bool {
	return s.ID == 1
}

// Sites is a list of sites.
type Sites []Site

// UnscopedList lists all sites, not scoped to the current user.
func (s *Sites) UnscopedList(ctx context.Context) error {
	return errors.Wrap(zdb.MustGet(ctx).SelectContext(ctx, s,
		`/* Sites.List */ select * from sites where state=$1`,
		StateActive), "Sites.List")
}

// UnscopedListCnames all sites that have CNAME set, not scoped to the current
// user.
func (s *Sites) UnscopedListCnames(ctx context.Context) error {
	return errors.Wrap(zdb.MustGet(ctx).SelectContext(ctx, s, `/* Sites.ListCnames */
		select * from sites where state=$1 and cname is not null`,
		StateActive), "Sites.List")
}

// ListSubs lists all subsites for the current site.
func (s *Sites) ListSubs(ctx context.Context) error {
	return errors.Wrap(zdb.MustGet(ctx).SelectContext(ctx, s, `/* Sites.ListSubs */
		select * from sites where parent=$1 and state=$2 order by code`,
		MustGetSite(ctx).ID, StateActive), "Sites.ListSubs")
}

// ContainsCNAME reports if there is a site with this CNAME set.
func (s *Sites) ContainsCNAME(ctx context.Context, cname string) (bool, error) {
	var ok bool
	err := zdb.MustGet(ctx).GetContext(ctx, &ok, `/* Sites.ContainsCNAME */
		select 1 from sites where lower(cname)=lower($1) limit 1`, cname)
	return ok, errors.Wrapf(err, "Sites.ContainsCNAME for %q", cname)
}

// OldSoftDeleted finds all sites which have been soft-deleted more than a week
// ago.
func (s *Sites) OldSoftDeleted(ctx context.Context) error {
	return errors.Wrap(zdb.MustGet(ctx).SelectContext(ctx, s, fmt.Sprintf(`/* Sites.OldSoftDeleted */
		select * from sites where state=$1 and updated_at < %s`, interval(ctx, 7)),
		StateDeleted), "Sites.OldSoftDeleted")
}
