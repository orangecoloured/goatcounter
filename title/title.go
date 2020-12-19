// Copyright © 2019 Martin Tournoij <martin@arp242.net>
// This file is part of GoatCounter and published under the terms of the EUPL
// v1.2, which can be found in the LICENSE file or at http://eupl12.zgo.at

// Package title fetches a HTML page's <title>
package title

import (
	"net/http"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"zgo.at/errors"
)

var client = http.Client{Timeout: 5 * time.Second}

// Get the text contents of a page's <title> element.
//
// Note this won't run any JavaScript; so if a title is changed in JS based on
// the URL fragment then the result will be wrong.
func Get(url string) (string, error) {
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", errors.Wrap(err, "title.Get")
	}
	r.Header.Set("User-Agent", "GoatCounter/1.0 titlebot")

	resp, err := client.Do(r)
	if err != nil {
		return "", errors.Wrap(err, "title.Get")
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "title.Get")
	}
	title := doc.Find("head title")
	if title == nil {
		return "", nil
	}
	title = title.First()

	text := strings.TrimSpace(title.Text())
	return text, nil
}
