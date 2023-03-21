package britive

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/mwlng/go-okta/pkg/okta"
)

type BritiveClient struct {
	britive    *Britive
	httpClient http.Client
	oktaClient *okta.OktaClient
}

func NewClient(britive *Britive, oktaClient *okta.OktaClient) *BritiveClient {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatal(err)

	}
	httpClient := http.Client{
		Jar: jar,
	}

	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return errors.New("Redirect")
	}

	return &BritiveClient{
		britive:    britive,
		httpClient: httpClient,
		oktaClient: oktaClient,
	}
}

func (bc *BritiveClient) LoginWithOkta(password, authToken string) error {
	loginEndpoint := fmt.Sprintf("%s/login?token=%s", bc.britive.TenentUrl, authToken)
	req, _ := http.NewRequest("GET", loginEndpoint, nil)
	_, err := bc.httpClient.Do(req)
	if err != nil {
		return err
	}

	authEndpoint := fmt.Sprintf("%s/api/auth", bc.britive.TenentUrl)
	britiveAuthData := &BritiveAuthData{
		AuthParameters: BritiveAuthParameters{
			Username:  bc.britive.Username,
			Challenge: "VALIDATE_USER",
			CliToken:  authToken,
			Type:      "CLI",
		},
	}
	authData, _ := json.Marshal(britiveAuthData)
	req, _ = http.NewRequest("POST", authEndpoint, strings.NewReader(string(authData)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := bc.httpClient.Do(req)
	if err != nil {
		return err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var authResultData BritiveAuthResultData
	json.Unmarshal(bodyBytes, &authResultData)
	loginUrl := strings.ReplaceAll(
		authResultData.AuthenticationResult.ChallengeParameters.LoginUrl,
		" ",
		"%20")

	var redirectUrl = ""
	verifyCode, _ := bc.britive.GenerateVerifier()
	challengeCode, _ := bc.britive.GenerateAuthToken(verifyCode, "sha256")
	oauthUrl := fmt.Sprintf("%s&redirect_uri=%s/login&code_challenge=%s&code_challenge_method=S256", loginUrl, bc.britive.TenentUrl, challengeCode)
	req, _ = http.NewRequest("GET", oauthUrl, nil)
	_, err = bc.httpClient.Do(req)
	if err != nil {
		redirectUrl = bc.extractRedirectUrl("Get", err)
		if redirectUrl == "" {
			return err
		}
	}
	britiveSAMLUrl := redirectUrl

	req, _ = http.NewRequest("GET", redirectUrl, nil)
	_, err = bc.httpClient.Do(req)
	if err != nil {
		redirectUrl = bc.extractRedirectUrl("Get", err)
		if redirectUrl == "" {
			return err
		}
	}

	req, _ = http.NewRequest("GET", redirectUrl, nil)
	_, err = bc.httpClient.Do(req)
	if err != nil {
		redirectUrl = bc.extractRedirectUrl("Get", err)
		if redirectUrl == "" {
			return err
		}
	}

	bc.oktaClient.CookieJar = bc.httpClient.Jar
	err = bc.oktaClient.AuthenticateUser(password)
	if err != nil {
		return err
	}
	cookies := bc.oktaClient.CookieJar.Cookies(bc.oktaClient.BaseURL)
	bc.httpClient.Jar.SetCookies(bc.oktaClient.BaseURL, cookies)

	token, err := bc.authenticateWithOkta(britiveSAMLUrl, verifyCode, &authResultData)
	if err != nil {
		return err
	}

	britiveAuthData = &BritiveAuthData{
		AuthParameters: BritiveAuthParameters{
			AccessToken:  token.AccessToken,
			IdToken:      token.IdToken,
			RefreshToken: token.RefreshToken,
			Challenge:    "VALIDATE_TOKEN",
			CliToken:     authToken,
			Type:         "CLI",
		},
	}
	authData, _ = json.Marshal(britiveAuthData)
	req, _ = http.NewRequest("POST", authEndpoint, strings.NewReader(string(authData)))
	req.Header.Set("Content-Type", "application/json")
	resp, err = bc.httpClient.Do(req)
	if err != nil {
		return err
	}

	bodyBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func (bc *BritiveClient) extractRedirectUrl(method string, err error) string {
	regexStr := fmt.Sprintf("^%s \"(.*)\": Redirect$", method)
	r := regexp.MustCompile(regexStr)
	redirectUrl := string(r.FindStringSubmatch(err.Error())[1])

	return redirectUrl
}
