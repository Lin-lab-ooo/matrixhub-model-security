// Copyright The MatrixHub Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package repo

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/matrixhub-ai/matrixhub/internal/domain/security"
)

func TestSecurityReportEvidencePersistsWithoutPointerAliasing(t *testing.T) {
	store, _ := securityTestStore(t)
	enqueueSecurityTask(t, store, "alpha/m")
	claim := claimSecurityTask(t, store)
	report := completeSecurityReport(claim)
	report.State = security.Block
	finding := securityEvidenceFinding()
	finding.Evidence.ArchiveMemberChain = []security.ArchiveMemberEvidence{{MemberIndex: securityEvidenceNumber(0), NameSHA256: strings.Repeat("b", 64)}}
	report.Files[0].Findings = []security.Finding{finding}
	want := *finding.Evidence
	want.StreamIndex = securityEvidenceNumber(0)
	want.OpcodeOffset = securityEvidenceNumber(0)
	want.ArchiveMemberChain = []security.ArchiveMemberEvidence{{MemberIndex: securityEvidenceNumber(0), NameSHA256: strings.Repeat("b", 64)}}
	accepted, err := store.Finish(context.Background(), claim, report)
	require.NoError(t, err)
	require.True(t, accepted)

	// Mutation after publication must not change the persisted report or cache.
	*finding.Evidence.StreamIndex = 5
	*finding.Evidence.OpcodeOffset = 100
	*finding.Evidence.ArchiveMemberChain[0].MemberIndex = 9
	finding.Evidence.ArchiveMemberChain[0].NameSHA256 = strings.Repeat("c", 64)
	_, current, err := store.Get(context.Background(), claim.Repo, claim.Revision, claim.Generation)
	require.NoError(t, err)
	require.NotNil(t, current)
	require.Equal(t, &want, current.Files[0].Findings[0].Evidence)
	historical, err := store.Historical(context.Background(), claim.Repo, report.ReportID)
	require.NoError(t, err)
	require.Equal(t, &want, historical.Files[0].Findings[0].Evidence)
	cached, err := store.Cached(context.Background(), claim.Repo, report.Files[0].Artifact, claim.Generation)
	require.NoError(t, err)
	require.NotNil(t, cached)
	require.Equal(t, &want, cached.Findings[0].Evidence)

	// Each DB read owns its nested evidence. A caller cannot mutate another read.
	*current.Files[0].Findings[0].Evidence.StreamIndex = 7
	*cached.Findings[0].Evidence.ArchiveMemberChain[0].MemberIndex = 11
	again, err := store.Historical(context.Background(), claim.Repo, report.ReportID)
	require.NoError(t, err)
	require.Equal(t, &want, again.Files[0].Findings[0].Evidence)
	require.Equal(t, &want, historical.Files[0].Findings[0].Evidence)
}
