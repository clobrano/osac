/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package servers

import (
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
)

const (
	sshKeyTenantScopedMessage                = "SSH key reference must be tenant-scoped."
	computeInstanceSSHKeyInvalidScopeMessage = "SSH key reference is invalid for the ComputeInstance tenant/project scope."
	catalogItemSSHKeyInvalidScopeMessage     = "SSH key reference is invalid for the CatalogItem tenant/project scope."
)

// validateTenantScopedSSHKeyReference rejects SSH Secret references marked as shared.
func validateTenantScopedSSHKeyReference(reference *privatev1.SecretReference) error {
	if reference != nil && reference.GetShared() {
		return grpcstatus.Error(grpccodes.InvalidArgument, sshKeyTenantScopedMessage)
	}
	return nil
}

func normalizeSSHKeyReferenceLookupError(err error, message string) error {
	if err == nil {
		return nil
	}
	switch grpcstatus.Code(err) {
	case grpccodes.InvalidArgument, grpccodes.NotFound, grpccodes.PermissionDenied:
		return grpcstatus.Error(grpccodes.InvalidArgument, message)
	default:
		return err
	}
}

// canonicalSSHKeySecretReference builds a reference from a resolved Secret's ID, name, and project.
func canonicalSSHKeySecretReference(secret *privatev1.Secret) *privatev1.SecretReference {
	return privatev1.SecretReference_builder{
		Id:      secret.GetId(),
		Name:    secret.GetMetadata().GetName(),
		Project: secret.GetMetadata().GetProject(),
	}.Build()
}
