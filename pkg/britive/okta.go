package britive

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/mwlng/go-okta/pkg/okta"
	"github.com/mwlng/go-okta/pkg/saml"
	"golang.org/x/net/html"
)

func (bc *BritiveClient) authenticateWithOkta(britiveSAMLUrl, verifyCode string, authResultData *BritiveAuthResultData) (*BritiveAuthToken, error) {
	var redirectUrl = ""

	httpClient := http.Client{
		//Transport: transCfg,
		//Timeout:   Timeout,
		Jar: bc.httpClient.Jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("Redirect")
		},
	}

	requestUrl := fmt.Sprintf("%s/%s", bc.oktaClient.BaseURL, "login/sessionCookieRedirect")
	req, _ := http.NewRequest("GET", requestUrl, nil)
	q := req.URL.Query()
	q.Add("checkAccountSetupComplete", "true")
	q.Add("token", bc.oktaClient.UserAuth.SessionToken)
	q.Add("redirectUrl", britiveSAMLUrl)
	req.URL.RawQuery = q.Encode()
	_, err := httpClient.Do(req)
	if err != nil {
		redirectUrl = bc.extractRedirectUrl("Get", err)
		if redirectUrl == "" {
			return nil, err
		}
	}

	req, _ = http.NewRequest("GET", redirectUrl, nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	doc, err := html.Parse(strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, err
	}
	samlResponse, _ := okta.GetNode(doc, "SAMLResponse")
	relayState, _ := okta.GetNode(doc, "RelayState")
	requestParams := url.Values{}
	requestParams.Add("SAMLResponse", samlResponse)
	requestParams.Add("RelayState", relayState)

	samlAssertion := saml.SAMLAssertion{}
	err = okta.ParseSAML(bodyBytes, &samlAssertion)
	if err != nil {
		return nil, err
	}
	requestUrl = samlAssertion.Resp.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient
	req, _ = http.NewRequest("POST", requestUrl, strings.NewReader(requestParams.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = httpClient.Do(req)
	if err != nil {
		redirectUrl = bc.extractRedirectUrl("Post", err)
		if redirectUrl == "" {
			return nil, err
		}
	}

	req, _ = http.NewRequest("GET", redirectUrl, nil)
	_, err = httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	loginCodeUrl, _ := url.Parse(redirectUrl)
	loginParams, _ := url.ParseQuery(loginCodeUrl.RawQuery)
	ssoSignInUrl, _ := url.Parse(authResultData.AuthenticationResult.ChallengeParameters.LoginUrl)
	ssoParams, _ := url.ParseQuery(ssoSignInUrl.RawQuery)
	requestParams = url.Values{}
	requestParams.Add("grant_type", "authorization_code")
	requestParams.Add("client_id", ssoParams["client_id"][0])
	requestParams.Add("code", loginParams["code"][0])
	requestParams.Add("code_verifier", verifyCode)
	requestParams.Add("redirect_uri", fmt.Sprintf("%s://%s/login", loginCodeUrl.Scheme, loginCodeUrl.Host))
	oauthTokenEndpoint := fmt.Sprintf("%s://%s/oauth2/token", ssoSignInUrl.Scheme, ssoSignInUrl.Host)
	req, _ = http.NewRequest("POST", oauthTokenEndpoint, strings.NewReader(requestParams.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	bodyBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var authToken BritiveAuthToken
	json.Unmarshal(bodyBytes, &authToken)

	return &authToken, nil
}
