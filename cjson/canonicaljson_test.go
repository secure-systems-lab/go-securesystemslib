package cjson

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type keyVal struct {
	Private     string `json:"private"`
	Public      string `json:"public"`
	Certificate string `json:"certificate,omitempty"`
}

type key struct {
	KeyID               string   `json:"keyid"`
	KeyIDHashAlgorithms []string `json:"keyid_hash_algorithms"`
	KeyType             string   `json:"keytype"`
	KeyVal              keyVal   `json:"keyval"`
	Scheme              string   `json:"scheme"`
}

func TestEncodeCanonical(t *testing.T) {
	objects := []interface{}{
		key{},
		key{
			KeyVal: keyVal{
				Private: "priv",
				Public:  "pub",
			},
			KeyIDHashAlgorithms: []string{"hash"},
			KeyID:               "id",
			KeyType:             "type",
			Scheme:              "scheme",
		},
		map[string]interface{}{
			"true":   true,
			"false":  false,
			"nil":    nil,
			"int":    3,
			"int2":   float64(42),
			"string": `\"`,
		},
		key{
			KeyVal: keyVal{
				Certificate: "cert",
				Private:     "priv",
				Public:      "pub",
			},
			KeyIDHashAlgorithms: []string{"hash"},
			KeyID:               "id",
			KeyType:             "type",
			Scheme:              "scheme",
		},
		json.RawMessage(`{"_type":"targets","spec_version":"1.0","version":0,"expires":"0001-01-01T00:00:00Z","targets":{},"custom":{"test":true}}`),
	}
	expectedResult := []string{
		`{"keyid":"","keyid_hash_algorithms":null,"keytype":"","keyval":{"private":"","public":""},"scheme":""}`,
		`{"keyid":"id","keyid_hash_algorithms":["hash"],"keytype":"type","keyval":{"private":"priv","public":"pub"},"scheme":"scheme"}`,
		`{"false":false,"int":3,"int2":42,"nil":null,"string":"\\\"","true":true}`,
		`{"keyid":"id","keyid_hash_algorithms":["hash"],"keytype":"type","keyval":{"certificate":"cert","private":"priv","public":"pub"},"scheme":"scheme"}`,
		`{"_type":"targets","custom":{"test":true},"expires":"0001-01-01T00:00:00Z","spec_version":"1.0","targets":{},"version":0}`,
	}
	for i := 0; i < len(objects); i++ {
		result, err := EncodeCanonical(objects[i])

		if string(result) != expectedResult[i] || err != nil {
			t.Errorf("EncodeCanonical returned (%s, %s), expected (%s, nil)",
				result, err, expectedResult[i])
		}
	}
}

func TestEncodeCanonicalErr(t *testing.T) {
	objects := []interface{}{
		map[string]interface{}{"float": 3.14159265359},
		TestEncodeCanonical,
	}
	errPart := []string{
		"Can't canonicalize floating point number",
		"unsupported type: func(",
	}

	for i := 0; i < len(objects); i++ {
		result, err := EncodeCanonical(objects[i])
		if err == nil || !strings.Contains(err.Error(), errPart[i]) {
			t.Errorf("EncodeCanonical returned (%s, %s), expected '%s' error",
				result, err, errPart[i])
		}
	}
}

func TestEncodeCanonicalHelper(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("encodeCanonical did not panic as expected")
		}
	}()

	objects := []interface{}{
		TestEncodeCanonicalHelper,
		[]interface{}{TestEncodeCanonicalHelper},
	}

	for i := 0; i < len(objects); i++ {
		var result strings.Builder
		err := encodeCanonical(objects[i], &result)
		assert.Nil(t, err)
	}
}

// -----------------------------------------------------------------------------

// Size 146b
var smallFixture = json.RawMessage(`{"keyid":"id","keyid_hash_algorithms":["hash"],"keytype":"type","keyval":{"certificate":"cert","private":"priv","public":"pub"},"scheme":"scheme"}`)

// Response from Github Webhook. Size: 2.7kb
var mediumFixture = json.RawMessage(`{"after":"1481a2de7b2a7d02428ad93446ab166be7793fbb","before":"17c497ccc7cca9c2f735aa07e9e3813060ce9a6a","commits":[{"added":[],"author":{"email":"lolwut@noway.biz","name":"Garen Torikian","username":"octokitty"},"committer":{"email":"lolwut@noway.biz","name":"Garen Torikian","username":"octokitty"},"distinct":true,"id":"c441029cf673f84c8b7db52d0a5944ee5c52ff89","message":"Test","modified":["README.md"],"removed":[],"timestamp":"2013-02-22T13:50:07-08:00","url":"https://github.com/octokitty/testing/commit/c441029cf673f84c8b7db52d0a5944ee5c52ff89"},{"added":[],"author":{"email":"lolwut@noway.biz","name":"Garen Torikian","username":"octokitty"},"committer":{"email":"lolwut@noway.biz","name":"Garen Torikian","username":"octokitty"},"distinct":true,"id":"36c5f2243ed24de58284a96f2a643bed8c028658","message":"This is me testing the windows client.","modified":["README.md"],"removed":[],"timestamp":"2013-02-22T14:07:13-08:00","url":"https://github.com/octokitty/testing/commit/36c5f2243ed24de58284a96f2a643bed8c028658"},{"added":["words/madame-bovary.txt"],"author":{"email":"lolwut@noway.biz","name":"Garen Torikian","username":"octokitty"},"committer":{"email":"lolwut@noway.biz","name":"Garen Torikian","username":"octokitty"},"distinct":true,"id":"1481a2de7b2a7d02428ad93446ab166be7793fbb","message":"Rename madame-bovary.txt to words/madame-bovary.txt","modified":[],"removed":["madame-bovary.txt"],"timestamp":"2013-03-12T08:14:29-07:00","url":"https://github.com/octokitty/testing/commit/1481a2de7b2a7d02428ad93446ab166be7793fbb"}],"compare":"https://github.com/octokitty/testing/compare/17c497ccc7cc...1481a2de7b2a","created":false,"deleted":false,"forced":false,"head_commit":{"added":["words/madame-bovary.txt"],"author":{"email":"lolwut@noway.biz","name":"Garen Torikian","username":"octokitty"},"committer":{"email":"lolwut@noway.biz","name":"Garen Torikian","username":"octokitty"},"distinct":true,"id":"1481a2de7b2a7d02428ad93446ab166be7793fbb","message":"Rename madame-bovary.txt to words/madame-bovary.txt","modified":[],"removed":["madame-bovary.txt"],"timestamp":"2013-03-12T08:14:29-07:00","url":"https://github.com/octokitty/testing/commit/1481a2de7b2a7d02428ad93446ab166be7793fbb"},"pusher":{"email":"lolwut@noway.biz","name":"Garen Torikian"},"ref":"refs/heads/master","repository":{"created_at":1332977768,"description":"","fork":false,"forks":0,"has_downloads":true,"has_issues":true,"has_wiki":true,"homepage":"","id":3860742,"language":"Ruby","master_branch":"master","name":"testing","open_issues":2,"owner":{"email":"lolwut@noway.biz","name":"octokitty"},"private":false,"pushed_at":1363295520,"size":2156,"stargazers":1,"url":"https://github.com/octokitty/testing","watchers":1}}`)

// Response from Facebook. Size: 6.5kb
var largeFixture = json.RawMessage(`{"stat":"ok","profile":{"providerName":"Facebook","identifier":"http://www.facebook.com/profile.php?id=100BlahBlah7767","verifiedEmail":"2013-11-22 21:01:09.601637 +0000","preferredUsername":"RpxDoc","displayName":"Rpx Doc","name":{"formatted":"Rpx Doc","givenName":"Rpx","familyName":"Doc"},"email":"rpxdoc@yahoo.com","url":"http://www.facebook.com/rpx.doc","photo":"https://graph.facebook.com/100BlahBlah7767/picture?type=large","utcOffset":"-08:00","address":{"formatted":"Portland, Oregon","type":"currentLocation"},"birthday":"1994-05-19","gender":"female"},"merged_poco":{"id":"http://www.facebook.com/profile.php?id=100BlahBlah7767","displayName":"Rpx Doc","preferredUsername":"RpxDoc","gender":"female","aboutMe":"i test stuff","profileUrl":"http://www.facebook.com/rpx.doc","relationshipStatus":"Widowed","religion":"u0627u0644u0627u0633u0644u0627u0645","status":"set_status timestamp test: Wed, 17 Oct 12 21:36:34 +0000","currentLocation":{"formatted":"Portland, Oregon"},"politicalViews":"Bude mu00edt toto vejce vu00edce fanouu0161ku016f neu017e Jiu0159u00ed Paroubek ?","name":{"formatted":"Rpx Doc","givenName":"Rpx","familyName":"Doc"},"updated":"2012-09-13T00:44:03.000Z","birthday":"1994-05-19","utcOffset":"-08:00","emails":[{"value":"rpxdoc@yahoo.com","type":"other","primary":true}],"languagesSpoken":["Pig Latin"],"urls":[{"value":"http://www.facebook.com/rpx.doc","type":"profile"},{"value":"http://www.facepalm.org","type":"other"},{"value":"http://foo.com","type":"other"}],"addresses":[{"formatted":"Portland, Oregon","type":"currentLocation"},{"formatted":"Luxembourg","type":"hometown"}],"books":["Dr. Seuss' The Cat in the Hat","Good Omens"],"movies":["Gigli","Big Trouble in Little China"],"music":["My favorite playlist","Country music","Western"],"tvShows":["Voltran","American Idol","ThunderCats","Seinfeld"],"quotes":["I'm getting ENOSPACE writing to /dev/null."],"interests":["Justin Bieber"],"sports":["Frolf","Underwater hockey"],"heroes":["Donkey","Shrek"],"activities":["Underwater basket weaving"],"photos":[{"value":"https://graph.facebook.com/100BlahBlah7767/picture?type=small","type":"other"},{"value":"https://graph.facebook.com/100BlahBlah7767/picture?type=large","type":"other","primary":true},{"value":"https://graph.facebook.com/100BlahBlah7767/picture?type=square","type":"other"},{"value":"https://graph.facebook.com/100BlahBlah7767/picture?type=normal","type":"other"}],"organizations":[{"name":"Janrain","title":"Tester","type":"job","startDate":"2007-05","description":"I am."},{"name":"Janrain","title":"a wee tester","type":"job","startDate":"0000-00","description":"something clever"},{"name":"Janrain","title":"To Test","type":"job","startDate":"2009-01","endDate":"2009-02"},{"name":"Janrain","title":"Testing Monkey","type":"job","startDate":"2006-02","endDate":"2005-02","description":"I was."},{"name":"School Of Rock","type":"High School"},{"name":"Hogwarts School of Witchcraft and Wizardry","type":"College"}]},"friends":["http://www.facebook.com/profile.php?id=1234BlahBlah254","http://www.facebook.com/profile.php?id=1234BlahBlah434","http://www.facebook.com/profile.php?id=1234BlahBlah662"],"provider":{"facebook":{"albums":[{"id":"326BlahBlah6808","name":"Untitled Album","link":"http://www.facebook.com/album.php?fbid=1234BlahBlah808&id=100BlahBlah7767&aid=78839","privacy":"custom","type":"normal"},{"id":"326BlahBlah0163","name":"Timeline Photos","link":"http://www.facebook.com/album.php?fbid=326BlahBlah0163&id=100BlahBlah7767&aid=78838","privacy":"everyone","type":"wall"},{"id":"322BlahBlah7306","name":"Cover Photos","link":"http://www.facebook.com/album.php?fbid=322BlahBlah7306&id=100BlahBlah7767&aid=77860","privacy":"everyone","type":"normal"},{"id":"322BlahBlah1017","name":"Untitled Album","link":"http://www.facebook.com/album.php?fbid=322BlahBlah1017&id=100BlahBlah7767&aid=77858","privacy":"custom","type":"normal"},{"id":"102BlahBlah3100","name":"Profile Pictures","link":"http://www.facebook.com/album.php?fbid=102BlahBlah3100&id=100BlahBlah7767&aid=4035","privacy":"everyone","type":"profile"}],"games":[{"name":"Axis & Allies","category":"Interest","id":"124BlahBlah6166"},{"name":"UNO","category":"Games/toys","id":"123BlahBlah6939"}],"groups":[{"name":"Test group","id":"123BlahBlah2994"},{"name":"Exploratory Group","id":"123BlahBlah7259"}],"videos":[{"id":"350BlahBlah1104","description":"a super awesome movie!!!","picture":"http://example.com/hvthumb-ak-snc6/245400_350BlahBlah1061_350BlahBlah1104_2773_417_t.jpg","icon":"http://example.com/rsrc.php/v2/yD/r/DggBlahz4tO.gif","embed_html":"","source":"http://example.com/cfs-ak-ash4/v/34xyz3/743/350BlahBlah1104_8269.mp4?oh=3f74c5a67BlahBlah33eb2d7f72d0dc1&oe=5080CF78&__gda__=1350674533_97d8568b1a07387e4cee5d02d87262b9"},{"id":"123BlahBlah7762","description":"what what!","picture":"http://example.com/hvthumb-ak-ash4/245318_350BlahBlah4397_350BlahBlah7762_37327_361_t.jpg","icon":"http://example.com/rsrc.php/v2/yD/r/DggBlahz4tO.gif","embed_html":"","source":"http://example.com/cfs-ak-snc7/v/610161/125/350BlahBlah7762_24214.mp4?oh=3f527BlahBlahBlahBlah8dd9c665ba0&oe=5080F026&__gda__=1350Blah08_f3da7404BlahBlah6f886b3fce52ea4a"}]}},"limited_data":"false","accessCredentials":{"accessToken":"AAAFArLqJQIBlahBlaha0rCdu9m5d5fBlahBlahFKYWpp401H9LGf5rQasuZAzrMyoZA9J45FDSZACLyNCXkAZAgpDFr0hG8NBkb8CccXXuQZDZD","uid":"100BlahBlah7767","expires":1355690751,"scopes":"email,publish_stream,user_birthday,user_location,user_hometown,user_relationships,user_interests,user_about_me,user_photos,user_work_history,friends_hometown,friends_interests,friends_relationships,friends_photos,friends_location,friends_about_me,friends_birthday,friends_work_history,read_stream,read_insights,create_event,rsvp_event,sms,read_requests,read_mailbox,read_friendlists,xmpp_login,ads_management,manage_pages,user_checkins,friends_checkins,publish_checkins,user_online_presence,friends_online_presence,user_education_history,friends_education_history,user_religion_politics,friends_religion_politics,user_likes,manage_notifications,friends_actions.music,user_actions.music,user_activities,friends_likes,friends_relationship_details,publish_actions,friends_events,user_notes,friends_notes,friends_questions,friends_videos,user_website,friends_status,friends_activities,manage_friendlists,user_events,user_groups,friends_groups,user_questions,user_videos,friends_website","type":"Facebook"}}`)

func BenchmarkEncodeCanonical(b *testing.B) {
	var table = []struct {
		input json.RawMessage
	}{
		{input: smallFixture},
		{input: mediumFixture},
		{input: largeFixture},
	}

	for _, v := range table {
		b.Run(fmt.Sprintf("input_size_%d", len(v.input)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				EncodeCanonical(v.input) //nolint:errcheck
			}
		})
	}
}
