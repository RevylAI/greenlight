package codescan

import "regexp"

// ugcComplianceRules returns the Guideline 1.2 check for apps that embed a
// user-generated-content (chat/comments/social-feed) SDK with no visible
// moderation safeguard anywhere in the project.
//
// guidelines.json's own text for 1.2 is explicit: "Apps with UGC must have
// filtering, reporting, blocking, and content moderation," and its
// common_violations list "Missing content reporting mechanism," "No ability
// to block abusive users," "Inadequate content moderation," and "No method
// for users to flag inappropriate content" — but no rule anywhere in this
// project checked for any of it before this. The closest existing coverage,
// account-no-delete/iap-no-restore/social-login-no-apple/missing-att, all
// check a completely different set of project-level facts.
//
// Calibrated the same way crypto-exchange-sdk is calibrated, because the
// same lesson applies: a bare word like "comment," "post," or "message" is
// everywhere in ordinary code (a code comment, an HTTP POST, a log message)
// and would be a flood of false positives if matched directly. Instead the
// trigger only fires on a real, named UGC/chat/social SDK package identifier
// or native import — the class of app this guideline is actually about
// (chat, comments, forums, live social feeds), not every app that happens to
// send any kind of message.
func ugcComplianceRules() []Rule {
	return []Rule{
		&PatternRule{
			id:        "ugc-no-moderation-tools",
			title:     "User-generated-content SDK without visible moderation tools",
			guideline: "1.2",
			severity:  SeverityHigh,
			detail:    "A chat / comments / social-feed SDK is a dependency, but no reporting, blocking, flagging, or moderation functionality was found anywhere in the project. Guideline 1.2 requires apps with user-generated content to have filtering, reporting, blocking, and content moderation — App Review tests this by trying to post abusive content and looking for a way to report or block it.",
			fix:       "Add a real way for users to report content/users, block abusive users, and flag inappropriate content — and a moderation process behind it (automated filtering and/or human review). A support email alone is not enough; the mechanism must be reachable from inside the UGC surface itself. Silence with `// greenlight:ignore ugc-no-moderation-tools`, or in .greenlight.yml (`rules: { ugc-no-moderation-tools: { enabled: false } }`).",
			languages: []string{"swift", "objc", "typescript", "javascript"},
			patterns: []*regexp.Regexp{
				// Real UGC/chat/social SDK package identifiers (npm import/require
				// specifier or Swift/ObjC import) — never a bare English word, so
				// ordinary "comment"/"post"/"message" code can't match.
				regexp.MustCompile(`(?i)['"](stream-chat(-react-native)?|@sendbird/[\w.-]+|sendbird(-uikit-react-native|-syncmanager)?|@cometchat/[\w.-]+|cometchat-pro|cometchat-chat-uikit-react-native|pubnub|pubnub-chat|@pubnub/chat|twilio-conversations|@twilio/conversations|agora-rtm-sdk|react-native-gifted-chat|@talkjs/[\w.-]+|talkjs)(/[\w./-]+)?['"]`),
				regexp.MustCompile(`(?i)(import\s+StreamChat\b|import\s+SendBirdSDK\b|import\s+SendbirdChatSDK\b|import\s+CometChatPro\b|import\s+CometChatSDK\b|import\s+PubNub\b|import\s+AgoraRtmKit\b|import\s+TwilioConversationsClient\b)`),
			},
			antiPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(report\s*(a\s*)?(user|post|comment|content|message|abuse)|block\s*(a\s*)?user|flag\s*(as\s*)?(content|post|comment|message|inappropriate)|reportContent|reportUser|reportMessage|blockUser|flagContent|contentModeration|moderat(e|ion|ed))`),
			},
			antiPatternsGlobal: true,
			firstMatchOnly:     true,
		},
	}
}
