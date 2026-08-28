package shadowsocksserver

import (
	"errors"
	"testing"
)

func TestListenRejectsTraditionalSecondUser(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			cfg := Configuration{
				Generation: "gen-1",
				Listeners: []ListenRule{{
					ID: "listener-1", AgentID: "agent-1", Port: 8388, Method: method,
					Users: []User{{ID: "user-1", Name: "alice", SecretRef: "secret/user-1", SecretVersion: "v1", Enabled: true}},
				}},
			}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			next, _, err := cfg.CreateAccount(AccountSpec{ID: "user-2", Method: method}, "secret/user-2", "v1")
			if err != nil {
				t.Fatal(err)
			}
			if len(next.Listeners) != 2 || next.Listeners[0].Port == next.Listeners[1].Port {
				t.Fatalf("second traditional user must use a new port: %+v", next.Listeners)
			}
			cfg.Listeners[0].Users = append(cfg.Listeners[0].Users, User{ID: "user-2", Name: "bob", SecretRef: "secret/user-2", SecretVersion: "v1", Enabled: true})
			if err := cfg.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("validate second user: %v", err)
			}
		})
	}
}

func TestListenAllowsSS2022MultipleUsersAndUniquePorts(t *testing.T) {
	cfg := Configuration{
		Generation: "gen-1",
		Listeners: []ListenRule{
			{
				ID: "listener-1", AgentID: "agent-1", Port: 8388, Method: DefaultSS2022Method,
				ServerSecretRef: "secret/server-1", ServerSecretVersion: "v1",
				Users: []User{
					{ID: "user-1", Name: "alice", SecretRef: "secret/user-1", SecretVersion: "v1", Enabled: true},
					{ID: "user-2", Name: "bob", SecretRef: "secret/user-2", SecretVersion: "v1", Enabled: true},
				},
			},
			{
				ID: "listener-2", AgentID: "agent-1", Port: 8488, Method: DefaultSS2022Method,
				Users: []User{{ID: "user-3", Name: "carol", SecretRef: "secret/user-3", SecretVersion: "v1", Enabled: true}},
			},
			{
				ID: "listener-3", AgentID: "agent-2", Port: 8388, Method: "aes-256-gcm",
				Users: []User{{ID: "user-4", Name: "dave", SecretRef: "secret/user-4", SecretVersion: "v1", Enabled: true}},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	next, user, err := cfg.CreateAccount(AccountSpec{ID: "user-5", Name: "erin", Method: DefaultSS2022Method}, "secret/user-5", "v1")
	if err != nil || user.ID != "user-5" {
		t.Fatalf("append ss2022 user=%+v err=%v", user, err)
	}
	if err = next.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateListenDefaultsAndAppendDelete(t *testing.T) {
	cfg := Configuration{Generation: "gen-1"}
	user := User{ID: "user-1", Name: "alice", SecretRef: "secret/user-1", SecretVersion: "v1", Enabled: true}
	next, listener, created, err := cfg.CreateListen(ListenSpec{AgentID: "agent-1", Method: DefaultSS2022Method}, user, "secret/server-1", "v1")
	if err != nil || listener.Port != minAutoListenPort || listener.Method != DefaultSS2022Method || created.ID != "user-1" {
		t.Fatalf("create=%+v user=%+v err=%v", listener, created, err)
	}
	second := User{ID: "user-2", Name: "bob", SecretRef: "secret/user-2", SecretVersion: "v1", Enabled: true}
	next, listener, created, err = next.AppendListenUser(listener.ID, second)
	if err != nil || created.ID != "user-2" || len(listener.Users) != 2 {
		t.Fatalf("append=%+v err=%v", listener, err)
	}
	next, _, err = next.DeleteUser("user-1")
	if err != nil {
		t.Fatal(err)
	}
	kept, ok := next.User("user-2")
	if !ok || !kept.Enabled {
		t.Fatalf("kept=%+v", kept)
	}
	if _, ok = next.User("user-1"); ok {
		t.Fatal("deleted user still present")
	}
	listenID := listener.ID
	next, _, err = next.DeleteListen(listenID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok = next.Listen(listenID); ok {
		t.Fatal("deleted listen still present")
	}
}

func TestAppendListenUserRejectsTraditional(t *testing.T) {
	cfg := Configuration{
		Generation: "gen-1",
		Listeners: []ListenRule{{
			ID: "listener-1", AgentID: "agent-1", Port: 8388, Method: "aes-256-gcm",
			Users: []User{{ID: "user-1", SecretRef: "secret/user-1", SecretVersion: "v1", Enabled: true}},
		}},
	}
	_, _, _, err := cfg.AppendListenUser("listener-1", User{ID: "user-2", SecretRef: "secret/user-2", SecretVersion: "v1", Enabled: true})
	if !errors.Is(err, ErrTraditionalMultiUser) {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateListenRejectsDuplicatePort(t *testing.T) {
	cfg := Configuration{
		Generation: "gen-1",
		Listeners: []ListenRule{{
			ID: "listener-1", AgentID: "agent-1", Port: 8388, Method: DefaultSS2022Method,
			Users: []User{{ID: "user-1", SecretRef: "secret/user-1", SecretVersion: "v1", Enabled: true}},
		}},
	}
	_, _, _, err := cfg.CreateListen(ListenSpec{AgentID: "agent-1", Port: 8388, Method: DefaultSS2022Method}, User{ID: "user-2", SecretRef: "secret/user-2", SecretVersion: "v1"}, "secret/server-2", "v1")
	if !errors.Is(err, ErrPortConflict) {
		t.Fatalf("err=%v", err)
	}
}

func TestListenRejectsDuplicatePortOnSameAgent(t *testing.T) {
	cfg := Configuration{
		Generation: "gen-1",
		Listeners: []ListenRule{
			{ID: "listener-1", AgentID: "agent-1", Port: 8388, Method: DefaultSS2022Method},
			{ID: "listener-2", AgentID: "agent-1", Port: 8388, Method: "aes-256-gcm", Users: []User{{ID: "user-1", SecretRef: "secret/user-1", SecretVersion: "v1", Enabled: true}}},
		},
	}
	if err := cfg.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate port: %v", err)
	}
}

func TestListenDefaultMethodIsSS2022Blake3AES128GCM(t *testing.T) {
	if DefaultSS2022Method != "2022-blake3-aes-128-gcm" {
		t.Fatalf("default method=%q", DefaultSS2022Method)
	}
	method, err := AccountSpec{}.resolveMethod("")
	if err != nil || method != DefaultSS2022Method {
		t.Fatalf("resolved=%q err=%v", method, err)
	}
}
