package britive

type Britive struct {
	TenentUrl string
	Username  string
	Profile   string
	Status    string
}

type BritiveAuthToken struct {
	IdToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type BritiveAuthData struct {
	AuthParameters BritiveAuthParameters `json:"authParameters"`
}

type BritiveAuthParameters struct {
	CliToken     string `json:"cliToken"`
	AccessToken  string `json:"AccessToken,omitempty"`
	Challenge    string `json:"challenge,omitempty"`
	IdToken      string `json:"IdToken,omitempty"`
	RefreshToken string `json:"RefreshToken,omitempty"`
	Type         string `json:"type,omitempty"`
	Username     string `json:"username,omitempty"`
}

type BritiveAuthResultData struct {
	AuthenticationResult BritiveAuthResult `json:"authenticationResult"`
}

type BritiveAuthResult struct {
	UserId              string                     `json:"userId"`
	Username            string                     `json:"username"`
	AccessToken         string                     `json:"accessToken"`
	RefreshToken        string                     `json:"refreshToken"`
	ChallengeParameters BritiveChallengeParameters `json:"challengeParameters"`
	MaxSessionTimeout   int                        `json:"maxSessionTimeout"`
	AuthTime            int                        `json:"authTime"`
	Success             bool                       `json:"success"`
	Type                string                     `json:"type"`
	User                string                     `json:"user"`
}

type BritiveChallengeParameters struct {
	LoginUrl  string `json:"loginUrl"`
	LogoutUrl string `json:"logoutUrl"`
	Challenge string `json:"challenge"`
}

type BritiveApplication struct {
	AppContainerId           string               `json:"appContainerId"`
	AppName                  string               `json:"appName"`
	AppDescription           string               `json:"appDescription"`
	IconUrl                  string               `json:"iconUrl "`
	CatalogAppName           string               `json:"catalogAppName"`
	ProgrammaticAccess       bool                 `json:"programmaticAccess"`
	ProgrammaticAccessError  BritiveError         `json:"programmaticAccessError,omitempty"`
	ConsoleAccess            bool                 `json:"consoleAccess"`
	ConsoleAccessError       BritiveError         `json:"consoleAccessError,omitempty"`
	RequireHierarchicalModel bool                 `json:"requireHierarchicalModel"`
	SupportSharedAccounts    bool                 `json:"supportSharedAccounts"`
	Profiles                 []BritiveProfile     `json:"profiles"`
	Environments             []BritiveEnvironment `json:"environments"`
}

type BritiveProfile struct {
	ProfileId          string               `json:"profileId"`
	ProfileName        string               `json:"profileName"`
	ProfileDescription string               `json:"profileDescription"`
	Environments       []BritiveEnvironment `json:"environments"`
	ConsoleAccess      bool                 `json:"consoleAccess"`
	ProgrammaticAccess bool                 `json:"programmaticAccess"`
}

type BritiveEnvironment struct {
	EnvironmentId            string           `json:"environmentId"`
	EnvironmentName          string           `json:"environmentName"`
	EnvironmentDescription   string           `json:"environmentDescription"`
	AlternateEnvironmentName string           `json:"alternateEnvironmentName"`
	AccountId                string           `json:"accountId"`
	Profiles                 []BritiveProfile `json:"profiles"`
}

type BritiveProfileStatus struct {
	AccessStatusId        int    `json:"accessStatusId"`
	UserId                int    `json:"userId"`
	UserIdStr             string `json:"userIdStr"`
	TransactionId         string `json:"transactionId"`
	Expiration            string `json:"expiration"`
	CheckedOut            string `json:"checkedOut"`
	CheckedIn             string `json:"checkedIn"`
	CurrentExtensionIndex int    `json:"currentExtensionIndex"`
	EnvironmentId         string `json:"environmentId"`
	AccessType            string `json:"accessType"`
	Status                string `json:"status"`
	StatusText            string `json:"statusText"`
	AppContainerId        string `json:"appContainerId"`
	PapId                 string `json:"papId"`
}

type BritiveError struct{}
