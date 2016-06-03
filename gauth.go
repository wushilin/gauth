/*
Provides oauth feature.
See DoOAuthBrowser()
See DoOAuthCmd()

Don't use other methods.
*/
package gauth

import (
	"bufio"
	bytes "bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

/*
Do OAUth with a client_secrets json file, an array of scopes,
a file to cache the credential so next time the auth won't be necessary.

	client_secrets_json_filename: The filename of the client secrets json file (you can download from cloud console)
	scopes: Array of strings for the authorization scopes. e.g. bigtable.Scope
	cacheFile: A file to store the access token, refresh token and expiry information.
	           If the cached credential is still valid, no oauth is done, instead, a client is returned immediately.
	           If the cached credential is not valid, an oauth via browser will be performed. This package will start
	           a local listener to receive the oauth token. Works best with apps runs locally. In SSH command mode where
	           you don't have a browser, use DoOAuthCmd function instead.
*/
func DoOAuthBrowser(client_secrets_json_filename string, scopes []string, cacheFile string) (*http.Client, *oauth2.Config) {
	ctx := context.Background()
	bytes, err := ioutil.ReadFile(client_secrets_json_filename)
	if err != nil {
		log.Panic(err)
		return nil, nil
	}
	config, err := google.ConfigFromJSON(bytes, scopes...)
	if err != nil {
		log.Panic(err)
		return nil, nil
	}
	return newOAuthClient(ctx, config, cacheFile, true), config
}

/*
Do OAUth with a client_secrets json file, an array of scopes,
a file to cache the credential so next time the auth won't be necessary.

	client_secrets_json_filename: The filename of the client secrets json file (you can download from cloud console)
	scopes: Array of strings for the authorization scopes. e.g. bigtable.Scope
	cacheFile: A file to store the access token, refresh token and expiry information.
	           If the cached credential is still valid, no oauth is done, instead, a client is returned immediately.
	           If the cached credential is not valid, an oauth via command line will be performed. The program will print
	           a url and ask user to go to the url in a browser, do oauth flow, and generate a response code to be pasted
	           back to the command line again. At the end of the process, a http client is returned.
*/

func DoOAuthCmd(client_secrets_json_filename string, scopes []string, cacheFile string) (*http.Client, *oauth2.Config) {
	ctx := context.Background()
	bytes, err := ioutil.ReadFile(client_secrets_json_filename)
	if err != nil {
		log.Panic(err)
		return nil, nil
	}
	config, err := google.ConfigFromJSON(bytes, scopes...)
	if err != nil {
		log.Panic(err)
		return nil, nil
	}
	return newOAuthClient(ctx, config, cacheFile, false), config
}

type FileReuseTokenSource struct {
	LastToken   *oauth2.Token
	FileName    string
	TokenSource oauth2.TokenSource
}

func NewFileReuseTokenSource(filename string, tokensource oauth2.TokenSource) *FileReuseTokenSource {
	token, err := tokenFromFile(filename)
	if err != nil {
		// no token yet
		return &FileReuseTokenSource{nil, filename, oauth2.ReuseTokenSource(nil, tokensource)}
	} else {
		// we have existing token!
		if token.Valid() {
			return &FileReuseTokenSource{token, filename, oauth2.ReuseTokenSource(token, tokensource)}
		} else {
			// as if it is not usable
			return &FileReuseTokenSource{nil, filename, oauth2.ReuseTokenSource(nil, tokensource)}
		}
	}
}

func (v *FileReuseTokenSource) Token() (*oauth2.Token, error) {
	//fmt.Println("Getting token")
	if v.LastToken != nil && v.LastToken.Valid() {
		return v.LastToken, nil
	}

	nextToken, err := v.TokenSource.Token()
	if err != nil {
		// something wrong
		return nil, err
	} else {
		// fmt.Println(nextToken.Expiry)
		// fmt.Println("Faking expiry")
		// nextToken.Expiry = time.Now().Add(200*time.Millisecond)
		// I have a new token, update if necessary
		if v.LastToken != nil && nextToken.AccessToken == v.LastToken.AccessToken {
			// no update required
			//fmt.Println("Still getting the old one, I am happy, not replacing file")
		} else {
			//fmt.Println("Oh what? token changed? update token now!")
			v.LastToken = nextToken
			saveToken(v.FileName, nextToken)
		}
		return nextToken, nil
	}

}

func TokenSource() {

}

func DoOAuthServiceAccount(client_secrets_json_filename string, scopes []string, cacheFile string) (*http.Client, *jwt.Config) {
	ctx := context.Background()
	bytes, err := ioutil.ReadFile(client_secrets_json_filename)
	if err != nil {
		log.Panic(err)
		return nil, nil
	}
	config, err := google.JWTConfigFromJSON(bytes, scopes...)
	if err != nil {
		log.Panic(err)
		return nil, nil
	}
	tokenSource := config.TokenSource(ctx)
	nts := NewFileReuseTokenSource(cacheFile, tokenSource)
	return oauth2.NewClient(ctx, nts), config
}

func getAnyName(target interface{}) string {
	for k, _ := range target.(map[string]interface{}) {
		return k
	}
	return "*"
}

/**
path1.path2.path3
path1.path2[1].path3[1]
**/
func JsonAccess(data map[string]interface{}, path string) (resultObject interface{}) {
	defer func() {
		if err := recover(); err != nil {
			resultObject = nil
			return
		}
	}()
	tokens := strings.Split(path, ".")
	var target interface{} = data
	for i := 0; i < len(tokens); i++ {
		nextToken := tokens[i]
		name, index := getAccessorNameAndIndex(nextToken)
		if name == "*" {
			name = getAnyName(target)
		}
		if index == -1 {
			target = target.(map[string]interface{})[name]
		} else {
			target = target.(map[string]interface{})[name].([]interface{})[index]
		}
	}
	return target
}

// returns the accessor name and index. Index is -1 if not array accessor
func getAccessorNameAndIndex(name string) (string, int) {
	matched, err := regexp.Match("^[^\\[\\]]+\\[\\d+\\]$", []byte(name))
	if err != nil {
		// should not happen
		return name, -1
	}
	if matched {
		// array accessor
		nameIndex := strings.LastIndex(name, "[")
		nameTag := name[:nameIndex]
		indexTag := name[nameIndex+1 : len(name)-1]
		indexVal, err := strconv.Atoi(indexTag)
		if err != nil {
			// malformed
			return name, -1
		}
		return nameTag, indexVal
	} else {
		// property accessor
		return name, -1
	}
}

func ReadFileAsString(filename string) (string, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	} else {
		return string(bytes), nil
	}
}

func newOAuthClient(ctx context.Context, config *oauth2.Config, cacheFile string, useBrowser bool) *http.Client {
	token, err := tokenFromFile(cacheFile)
	if err != nil {
		token = tokenFromFlow(ctx, config, useBrowser)
		saveToken(cacheFile, token)
	} else {
		log.Printf("Using cached token %#v from %q", token, cacheFile)
	}
	ts := config.TokenSource(ctx, token)
	nts := NewFileReuseTokenSource(cacheFile, ts)
	return oauth2.NewClient(ctx, nts)
}

func tokenFromFlow(ctx context.Context, config *oauth2.Config, useBrowser bool) *oauth2.Token {
	var code string
	randState := fmt.Sprintf("st%d", time.Now().UnixNano())
	if useBrowser {
		ch := make(chan string)
		ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if req.URL.Path == "/favicon.ico" {
				http.Error(rw, "", 404)
				return
			}
			if req.FormValue("state") != randState {
				log.Printf("State doesn't match: req = %#v", req)
				http.Error(rw, "", 500)
				return
			}
			if code = req.FormValue("code"); code != "" {
				fmt.Fprintf(rw, "<h1>Success</h1>Authorized.")
				rw.(http.Flusher).Flush()
				ch <- code
				return
			}
			log.Printf("no code")
			http.Error(rw, "", 500)
		}))
		defer ts.Close()
		config.RedirectURL = ts.URL
		authURL := config.AuthCodeURL(randState)
		go openURL(authURL)
		code = <-ch
	} else {
		config.RedirectURL = "urn:ietf:wg:oauth:2.0:oob"
		authURL := config.AuthCodeURL(randState)
		fmt.Println("Please open the following URL in your browser:")
		fmt.Println(authURL)
		fmt.Print("Please paste the code you received:")
		bio := bufio.NewReader(os.Stdin)
		codeb, _, _ := bio.ReadLine()
		code = string(codeb)
	}
	token, err := config.Exchange(ctx, code)
	log.Printf("Exchanged code [%s] for access token\n", code)
	log.Printf("AccessToken is [%s]\n", token.AccessToken)
	log.Printf("RefreshToken is [%s]\n", token.RefreshToken)
	if err != nil {
		log.Fatalf("Token exchange error: %v", err)
	}
	return token
}

func openURL(url string) {
	try := []string{"xdg-open", "google-chrome", "open"}
	for _, bin := range try {
		err := exec.Command(bin, url).Run()
		if err == nil {
			return
		}
	}
	log.Printf("Error opening URL in browser.")
}

func osUserCacheDir() string {
	return "."
}

func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	bytes_, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	fileContent := string(bytes_)
	if strings.Index(fileContent, "\"AccessToken\"") != -1 {
		// conversion is required
		//fmt.Println("Doing conversion here")
		mp := make(map[string]interface{})
		err = json.NewDecoder(strings.NewReader(fileContent)).Decode(&mp)
		if err != nil {
			return nil, err
		}
		accessToken := mp["AccessToken"]
		refreshToken := mp["RefreshToken"]
		expiry := mp["Expiry"]
		extra := mp["Extra"]

		var buffer bytes.Buffer
		mpnew := make(map[string]interface{})
		mpnew["access_token"] = accessToken
		mpnew["refresh_token"] = refreshToken
		mpnew["expiry"] = expiry
		mpnew["extra"] = extra

		err = json.NewEncoder(&buffer).Encode(mpnew)
		if err != nil {
			return nil, err
		}
		fileContent = buffer.String()
		//fmt.Println("Converted content:", fileContent)
	}

	t := new(oauth2.Token)
	err = json.NewDecoder(strings.NewReader(fileContent)).Decode(t)
	t.Expiry = time.Now()
	return t, err
}

func saveToken(file string, token *oauth2.Token) {
	f, err := os.Create(file)
	if err != nil {
		log.Printf("Warning: failed to cache oauth token: %v", err)
		return
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

