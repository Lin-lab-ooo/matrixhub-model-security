// Copyright The MatrixHub Authors. SPDX-License-Identifier: Apache-2.0
package repo

import (
	"testing"
	"time"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
	"github.com/stretchr/testify/require"
)

func TestSecurityOwnsClaimBindsEveryClaimIdentity(t *testing.T) {
	store, db := securityTestStore(t)
	enqueueSecurityTask(t, store, "alpha/m")
	claim := claimSecurityTask(t, store)
	owned, err := store.OwnsClaim(t.Context(), claim)
	require.NoError(t, err)
	require.True(t, owned)
	for name, change := range map[string]func(*security.Task){
		"id":         func(task *security.Task) { task.ID++ },
		"attempt":    func(task *security.Task) { task.Attempt++ },
		"token":      func(task *security.Task) { task.Token += "different" },
		"scope":      func(task *security.Task) { task.Scope = "different" },
		"repo":       func(task *security.Task) { task.Repo = "beta/m" },
		"revision":   func(task *security.Task) { task.Revision = "different" },
		"generation": func(task *security.Task) { task.Generation = "different" },
	} {
		t.Run(name, func(t *testing.T) {
			other := *claim
			change(&other)
			owned, err := store.OwnsClaim(t.Context(), &other)
			require.NoError(t, err)
			require.False(t, owned)
		})
	}
	require.NoError(t, db.Model(&securityTaskRow{}).Where("id = ?", claim.ID).Update("lease_until", time.Now().Add(-time.Second)).Error)
	owned, err = store.OwnsClaim(t.Context(), claim)
	require.NoError(t, err)
	require.False(t, owned)
}

func TestSecurityOwnsClaimRejectsCancellationAndRecreatedNamespace(t *testing.T) {
	for _, action := range []string{"cancel", "force", "recreate"} {
		t.Run(action, func(t *testing.T) {
			store, db := securityTestStore(t)
			task := enqueueSecurityTask(t, store, "alpha/m")
			claim := claimSecurityTask(t, store)
			switch action {
			case "cancel":
				cancelled, err := store.Cancel(t.Context(), task.ID, task.Repo)
				require.NoError(t, err)
				require.True(t, cancelled)
			case "force":
				task.UpdatedAt = time.Now()
				_, err := store.Enqueue(t.Context(), task, true)
				require.NoError(t, err)
			case "recreate":
				require.NoError(t, db.Exec("DELETE FROM projects WHERE name='alpha'").Error)
				require.NoError(t, db.Exec("INSERT INTO projects(name,type) VALUES ('alpha',0)").Error)
				require.NoError(t, db.Exec("INSERT INTO models(name,project_id,size,default_branch,parameter_count,readme_content) SELECT 'm',id,0,'main',0,'' FROM projects WHERE name='alpha'").Error)
			}
			owned, err := store.OwnsClaim(t.Context(), claim)
			require.NoError(t, err)
			require.False(t, owned)
		})
	}
}
