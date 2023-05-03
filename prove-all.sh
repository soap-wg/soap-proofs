./batch-run.sh SocialAuthentication --prove=SocialAuthentication
./batch-run.sh CodeVerifierSecrecy --prove=CodeVerifierSecrecy
./batch-run.sh HelperLemmata --prove=BrowserSessionSources --prove=BrowserSessionBinding --prove=BrowserSessionUnique --prove=UsernamesUnique --prove=UsernamesServerConfirmed --prove=PasswordsConfidential --prove=SignalKeysUnique --prove=IsPW --prove=CodeIsSingleUse --prove=UserAccountRequiresSignUp
./batch-run.sh SourcesLemma --prove=TokenFormatAndOTPLearning
./batch-run-privacy.sh
