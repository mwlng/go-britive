package britive

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/mwlng/go-britive/pkg/http"
)

func New(tenentUrl, username, profile string) *Britive {
	return &Britive{
		TenentUrl: tenentUrl,
		Username:  username,
		Profile:   profile,
		Status:    "",
	}
}

func (b *Britive) GetAccessToken(verifier string, retries int) (string, error) {
	data := BritiveAuthData{
		AuthParameters: BritiveAuthParameters{
			CliToken: verifier,
		},
	}

	jsonData, _ := json.Marshal(&data)
	accessTokenEndpoint := fmt.Sprintf("%s%s", b.TenentUrl, "/api/auth/cli/retrieve-tokens")
	count := 0
	for {
		resp, err := http.Post(accessTokenEndpoint, "", jsonData)

		if err != nil {
			count += 1
		} else {
			if authResult, ok := resp["authenticationResult"]; ok {
				return authResult.(map[string]interface{})["accessToken"].(string), nil
			} else {
				count += 1
			}
		}

		if count <= retries {
			count += 1
			time.Sleep(5 * time.Second)
		} else {
			break
		}
	}

	return "", nil
}

func (b *Britive) GenerateVerifier() (string, error) {
	randBytes, err := RandomBytes(32)
	if err != nil {
		return "", err
	}

	base64Str := base64.URLEncoding.EncodeToString(randBytes)

	return b.base64URLEncode(base64Str), nil
}

func (b *Britive) GenerateAuthToken(verifier, hashType string) (string, error) {
	var hasher hash.Hash
	hashType = strings.ToLower(hashType)
	if hashType == "sha512" {
		hasher = sha512.New()
	} else {
		hasher = sha256.New()
	}

	_, err := hasher.Write([]byte(verifier))
	if err != nil {
		return "", err
	}

	sha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	return b.base64URLEncode(sha), nil
}

func (b *Britive) base64URLEncode(input string) string {
	return strings.ReplaceAll(
		strings.ReplaceAll(
			strings.ReplaceAll(input, "+", "-"), "/", "_"),
		"=", "")
}

func RandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)

	_, err := rand.Read(bytes)
	if err != nil {
		return bytes, err
	}

	return bytes, nil
}

func (b *Britive) ListProfiles(accessToken string) ([]BritiveProfile, error) {
	accessEndpoint := fmt.Sprintf("%s%s", b.TenentUrl, "/api/access")
	resp, err := http.Get(accessEndpoint, accessToken, nil)
	if err != nil {
		return nil, err
	}

	var apps []BritiveApplication
	json.Unmarshal(resp, &apps)

	profiles := []BritiveProfile{}
	for _, app := range apps {
		//fmt.Printf("%+v\n", app)
		profiles = append(profiles, app.Profiles...)
	}

	return profiles, nil
}

func (b *Britive) CheckoutProgrammaticAccess(profileId, environmentId, accessToken, justification string) (map[string]interface{}, error) {
	checkoutEndpoint := fmt.Sprintf("%s/api/access/%s/environments/%s?accessType=PROGRAMMATIC", b.TenentUrl, profileId, environmentId)
	jsonData := []byte(fmt.Sprintf("{ \"justification\": \"%s\" }", justification))
	resp, err := http.Post(checkoutEndpoint, accessToken, jsonData)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *Britive) FetchCheckedOutPaps(accessToken string) ([]BritiveProfileStatus, error) {
	checkoutStatusEndpoint := fmt.Sprintf("%s/api/access/app-access-status", b.TenentUrl)
	params := http.HttpGetRequestParams{
		Params: map[string]string{
			"status": "checkedOut",
		},
	}
	resp, err := http.Get(checkoutStatusEndpoint, accessToken, &params)
	if err != nil {
		return nil, err
	}

	var paps []BritiveProfileStatus
	json.Unmarshal(resp, &paps)

	return paps, nil
}

func (b *Britive) CheckIn(transactionId, accessToken string) (map[string]interface{}, error) {
	checkInEndpoint := fmt.Sprintf("%s/api/access/%s", b.TenentUrl, transactionId)
	jsonStr := "{\"status\": \"checkedIn\"}"
	resp, err := http.Put(checkInEndpoint, accessToken, []byte(jsonStr))
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *Britive) FetchCheckedOutTokens(transactionId, accessToken string) (interface{}, error) {
	checkedOutTokensEndpoint := fmt.Sprintf("%s/api/access/%s/tokens", b.TenentUrl, transactionId)

	resp, err := http.Get(checkedOutTokensEndpoint, accessToken, nil)
	if err != nil {
		return nil, err
	}

	var creds *sts.Credentials
	json.Unmarshal(resp, &creds)

	return creds, nil
}

func (b *Britive) FetchTokens(profileId, environmentId, accessToken string) (interface{}, error) {
	fetchTokensEndpoint := fmt.Sprintf("%s/api/access/%s/environments/%s/tokens", b.TenentUrl, profileId, environmentId)
	fmt.Printf("%s\n", fetchTokensEndpoint)
	resp, err := http.Get(fetchTokensEndpoint, accessToken, nil)
	if err != nil {
		return nil, err
	}

	fmt.Printf("%+v\n", resp)

	return nil, nil
}
