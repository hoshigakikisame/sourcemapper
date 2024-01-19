package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

// sourceMap represents a sourceMap. We only really care about the sources and
// sourcesContent arrays.
type sourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// command line args
type config struct {
	outdir      string     // output directory
	url         string     // sourcemap url
	list        string     // filepath to list of sourcemap urls
	jsurl       string     // javascript url
	proxy       string     // upstream proxy server
	insecure    bool       // skip tls verification
	headers     headerList // additional user-supplied http headers
	concurrency int        // number of concurrent requests to make
	verbose     bool       // verbose output
}

type headerList []string

func outputHandler(text string, outputType string, verbose bool) {

	if !verbose && outputType != "err" {
		return
	}

	cRed := "\033[31m"
	cGreen := "\033[32m"
	cYellow := "\033[33m"

	switch outputType {
	case "info":
		log.Printf("%s[+] %s%s\n", cGreen, text, "\033[0m")
	case "warn":
		log.Printf("%s[!] %s%s\n", cYellow, text, "\033[0m")
	case "err":
		log.Fatalf("%s[!] %s%s\n", cRed, text, "\033[0m")
	default:
		log.Printf("%s[+] %s%s\n", cGreen, text, "\033[0m")
	}
}

func (i *headerList) String() string {
	return ""
}

func (i *headerList) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// getSourceMap retrieves a sourcemap from a URL or a local file and returns
// its sourceMap.
func getSourceMap(source string, headers []string, insecureTLS bool, proxyURL url.URL, verbose *bool) (m sourceMap, err error) {
	var body []byte
	var client http.Client

	outputHandler(fmt.Sprintf("Processing Sourcemap from %.1024s", source), "info", true)

	outputHandler(fmt.Sprintf("Retrieving Sourcemap from %.1024s\n", source), "info", *verbose)

	u, err := url.ParseRequestURI(source)
	if err != nil {
		// If it's a file, read it.
		body, err = os.ReadFile(source)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		if u.Scheme == "http" || u.Scheme == "https" {
			// If it's a URL, get it.
			req, err := http.NewRequest("GET", u.String(), nil)
			tr := &http.Transport{}

			if err != nil {
				log.Fatalln(err)
			}

			if insecureTLS {
				tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			}

			if proxyURL != (url.URL{}) {
				tr.Proxy = http.ProxyURL(&proxyURL)
			}

			client = http.Client{
				Transport: tr,
			}

			if len(headers) > 0 {
				headerString := strings.Join(headers, "\r\n") + "\r\n\r\n" // squish all the headers together with CRLFs

				outputHandler(fmt.Sprintf("Setting the following headers: \n%s", headerString), "info", *verbose)

				r := bufio.NewReader(strings.NewReader(headerString))
				tpReader := textproto.NewReader(r)
				mimeHeader, err := tpReader.ReadMIMEHeader()

				if err != nil {
					log.Fatalln(err)
				}

				req.Header = http.Header(mimeHeader)
			}

			res, err := client.Do(req)

			if err != nil {
				log.Fatalln(err)
			}

			body, err = io.ReadAll(res.Body)
			defer res.Body.Close()

			if res.StatusCode != 200 && len(body) > 0 {
				outputHandler(fmt.Sprintf("non-200 status code: %d - Confirm this URL contains valid source map manually!", res.StatusCode), "warn", *verbose)
				outputHandler("sourceMap URL request return != 200 - however, body length > 0 so continuing...", "warn", *verbose)
			}

			if err != nil {
				outputHandler(fmt.Sprintf("Error reading response body: %s", err), "err", *verbose)
			}
		} else if u.Scheme == "data" {
			urlchunks := strings.Split(u.Opaque, ",")
			if len(urlchunks) < 2 {
				outputHandler(fmt.Sprintf("Could not parse data URI - expected atleast 2 chunks but got %d\n", len(urlchunks)), "err", *verbose)
			}

			data, err := base64.StdEncoding.DecodeString(urlchunks[1])
			if err != nil {
				outputHandler(fmt.Sprintf("Error base64 decoding: %s", err), "err", *verbose)
			}

			body = []byte(data)
		} else {
			// If it's a file, read it.
			body, err = os.ReadFile(source)
			if err != nil {
				log.Fatalln(err)
			}
		}
	}
	// Unmarshall the body into the struct.
	outputHandler(fmt.Sprintf("Read %d bytes, parsing JSON.", len(body)), "info", *verbose)
	err = json.Unmarshal(body, &m)

	if err != nil {
		outputHandler("Error parsing JSON - confirm this is a valid JS sourcemap", "warning", *verbose)
	}

	return
}

// getSourceMapFromJS queries a JavaScript URL, parses its headers and content and looks for sourcemaps
// follows the rules outlined in https://tc39.es/source-map-spec/#linking-generated-code
func getSourceMapFromJS(jsurl string, headers []string, insecureTLS bool, proxyURL url.URL, verbose *bool) (m sourceMap, err error) {
	var client http.Client

	outputHandler(fmt.Sprintf("Processing JavaScript from URL: %.1024s", jsurl), "info", true)

	outputHandler(fmt.Sprintf("Retrieving JavaScript from URL: %s", jsurl), "info", *verbose)

	// perform the request
	u, err := url.ParseRequestURI(jsurl)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest("GET", u.String(), nil)
	tr := &http.Transport{}

	if err != nil {
		log.Fatalln(err)
	}

	if insecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	if proxyURL != (url.URL{}) {
		tr.Proxy = http.ProxyURL(&proxyURL)
	}

	client = http.Client{
		Transport: tr,
	}

	if len(headers) > 0 {
		headerString := strings.Join(headers, "\r\n") + "\r\n\r\n" // squish all the headers together with CRLFs
		outputHandler(fmt.Sprintf("Setting the following headers: \n%s", headerString), "info", *verbose)

		r := bufio.NewReader(strings.NewReader(headerString))
		tpReader := textproto.NewReader(r)
		mimeHeader, err := tpReader.ReadMIMEHeader()

		if err != nil {
			log.Fatalln(err)
		}

		req.Header = http.Header(mimeHeader)
	}

	res, err := client.Do(req)

	if err != nil {
		log.Fatalln(err)
	}

	if res.StatusCode != 200 {
		outputHandler(fmt.Sprintf("non-200 status code: %d - Confirm this URL contains valid source map manually!", res.StatusCode), "warn", *verbose)
	}

	var sourceMap string

	// check for SourceMap and X-SourceMap (deprecated) headers
	if sourceMap = res.Header.Get("SourceMap"); sourceMap == "" {
		sourceMap = res.Header.Get("X-SourceMap")
	}

	if sourceMap != "" {
		outputHandler(fmt.Sprintf("Found SourceMap URI in response headers: %s", sourceMap), "info", *verbose)
	} else {
		// parse the javascript
		body, err := io.ReadAll(res.Body)
		if err != nil {
			log.Fatalln(err)
		}
		defer res.Body.Close()

		// JS file can have multiple source maps in it, but only the last line is valid https://sourcemaps.info/spec.html#h.lmz475t4mvbx
		re := regexp.MustCompile(`\/\/[@#] sourceMappingURL=(.*)`)
		match := re.FindAllSubmatch(body, -1)

		if len(match) != 0 {
			// only the sourcemap at the end of the file should be valid
			sourceMap = string(match[len(match)-1][1])
			outputHandler(fmt.Sprintf("Found SourceMap in JavaScript body: %s", sourceMap), "info", *verbose)
		}
	}

	// this introduces a forced request bug if the JS file we're parsing is
	// malicious and forces us to make a request out to something dodgy - take care
	if sourceMap != "" {
		var sourceMapURL *url.URL
		// handle absolute/relative rules
		sourceMapURL, err = url.ParseRequestURI(sourceMap)
		if err != nil {
			// relative url...
			sourceMapURL, err = u.Parse(sourceMap)
			if err != nil {
				log.Fatal(err)
			}
		}

		return getSourceMap(sourceMapURL.String(), headers, insecureTLS, proxyURL, verbose)
	}

	err = errors.New("no sourcemap url found")
	return
}

// writeFile writes content to file at path p.
func writeFile(p string, content string, verbose *bool) error {
	p = filepath.Clean(p)

	if _, err := os.Stat(filepath.Dir(p)); os.IsNotExist(err) {
		// Using MkdirAll here is tricky, because even if we fail, we might have
		// created some of the parent directories.
		err = os.MkdirAll(filepath.Dir(p), 0700)
		if err != nil {
			return err
		}
	}

	outputHandler(fmt.Sprintf("Writing %d bytes to %s.", len(content), p), "info", *verbose)
	return os.WriteFile(p, []byte(content), 0600)
}

// cleanWindows replaces the illegal characters from a path with `-`.
func cleanWindows(p string) string {
	m1 := regexp.MustCompile(`[?%*|:"<>]`)
	return m1.ReplaceAllString(p, "")
}

func postProcess(sm *sourceMap, conf *config) {
	outputHandler(fmt.Sprintf("Retrieved Sourcemap with version %d, containing %d entries.", sm.Version, len(sm.Sources)), "info", conf.verbose)

	if len(sm.Sources) == 0 {
		outputHandler("No sources found.", "err", conf.verbose)
	}

	if len(sm.SourcesContent) == 0 {
		outputHandler("No source content found.", "err", conf.verbose)
	}

	if sm.Version != 3 && conf.verbose {
		outputHandler(fmt.Sprintf("Sourcemap version is %d, expected 3.", sm.Version), "warn", conf.verbose)
	}

	if _, err := os.Stat(conf.outdir); os.IsNotExist(err) {
		err = os.Mkdir(conf.outdir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}

	for i, sourcePath := range sm.Sources {
		sourcePath = "/" + sourcePath // path.Clean will ignore a leading '..', must be a '/..'
		// If on windows, clean the sourcepath.
		if runtime.GOOS == "windows" {
			sourcePath = cleanWindows(sourcePath)
		}

		// Use filepath.Join. https://parsiya.net/blog/2019-03-09-path.join-considered-harmful/
		scriptPath, scriptData := filepath.Join(conf.outdir, filepath.Clean(sourcePath)), sm.SourcesContent[i]
		err := writeFile(scriptPath, scriptData, &conf.verbose)
		if err != nil && conf.verbose {
			outputHandler(fmt.Sprintf("Error writing %s: %s", scriptPath, err), "warn", conf.verbose)
		}
	}

	outputHandler(fmt.Sprintf("Successfully wrote %d files to %s", len(sm.Sources), conf.outdir), "info", conf.verbose)
}

func main() {
	var proxyURL url.URL
	var conf config

	flag.StringVar(&conf.outdir, "output", "", "Source file output directory - REQUIRED")
	flag.StringVar(&conf.url, "url", "", "URL or path to the Sourcemap file - cannot be used with jsurl")
	flag.StringVar(&conf.jsurl, "jsurl", "", "URL to JavaScript file - cannot be used with url")
	flag.StringVar(&conf.list, "list", "", "File containing a list of Sourcemap URLs")
	flag.StringVar(&conf.proxy, "proxy", "", "Proxy URL")
	help := flag.Bool("help", false, "Show help")
	flag.BoolVar(&conf.insecure, "insecure", false, "Ignore invalid TLS certificates")
	flag.Var(&conf.headers, "header", "A header to send with the request, similar to curl's -H. Can be set multiple times, EG: \"./sourcemapper --header \"Cookie: session=bar\" --header \"Authorization: blerp\"")
	flag.IntVar(&conf.concurrency, "c", 10, "Number of concurrent requests to make")
	flag.BoolVar(&conf.verbose, "v", false, "Verbose output")
	flag.Parse()

	if *help || (conf.url == "" && conf.jsurl == "" && conf.list == "") || conf.outdir == "" {
		flag.Usage()
		return
	}

	if (conf.url == "") != (conf.jsurl == "") != (conf.list == "") {
		outputHandler("Multiple input options specified!", "warn", conf.verbose)
		flag.Usage()
		return
	}

	if conf.proxy != "" {
		p, err := url.Parse(conf.proxy)
		if err != nil {
			log.Fatal(err)
		}
		proxyURL = *p
	}

	// these need to just take the conf object
	if conf.url != "" {
		sm, err := getSourceMap(conf.url, conf.headers, conf.insecure, proxyURL, &conf.verbose)
		if err != nil {
			log.Fatal(err)
		}
		postProcess(&sm, &conf)
	} else if conf.jsurl != "" {
		sm, err := getSourceMapFromJS(conf.jsurl, conf.headers, conf.insecure, proxyURL, &conf.verbose)
		if err != nil {
			log.Fatal(err)
		}
		postProcess(&sm, &conf)
	} else if conf.list != "" {
		// read the file
		file, err := os.Open(conf.list)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		jobs := make(chan string)

		// start a worker pool of workers to process the jobs
		var wg sync.WaitGroup
		for i := 0; i < conf.concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range jobs {
					sm, err := getSourceMap(job, conf.headers, conf.insecure, proxyURL, &conf.verbose)
					if err != nil {
						outputHandler(fmt.Sprintf("Error retrieving sourcemap: %s", err), "warn", true)
						continue
					}
					postProcess(&sm, &conf)
				}
			}()
		}

		// assign jobs to the workers
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			jobs <- scanner.Text()
		}
	}
}
