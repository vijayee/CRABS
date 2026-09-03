#include <gtest/gtest.h>
extern "C" {
#include "../src/Attribute/attribute_machine.h"
#include "../src/Crypto/crypto.h"
}
#include "test_helpers.h"

// Audit N-3: the attribute machine now validates secp256k1 public keys at
// registration, so tests must use real generated keys (not 0xAB/0xCD fill).
static void _gen_pk(uint8_t out[33]) {
  ecdsa_keypair_t* kp = crypto_ecdsa_generate();
  ASSERT_NE(kp, nullptr);
  memcpy(out, kp->public_key, 33);
  crypto_ecdsa_keypair_destroy(kp);
}

class TestAttributeMachine : public ::testing::Test {
protected:
  attribute_machine_t* am;
  uint8_t admin_pk[33];

  void SetUp() override {
    _gen_pk(admin_pk);
    am = attribute_machine_create("admin", admin_pk);
  }

  void TearDown() override {
    attribute_machine_destroy(am);
  }
};

TEST_F(TestAttributeMachine, TestGenesis) {
  ASSERT_NE(am, nullptr);
  EXPECT_EQ(am->user_count, 1u);
  EXPECT_EQ(am->base_state.version, 1u);

  user_t* admin = attribute_machine_find_user(am, "admin");
  ASSERT_NE(admin, nullptr);
  EXPECT_STREQ(admin->user_id, "admin");
  EXPECT_EQ(admin->status, USER_ACTIVE);
  EXPECT_EQ(admin->key_version, 1u);
  EXPECT_EQ(admin->attribute_count, 1u);

  // Admin should have role:admin attribute
  attribute_value_t* attr = attribute_machine_find_attribute(admin, "role");
  ASSERT_NE(attr, nullptr);
  EXPECT_STREQ(attr->value, "role:admin");
  EXPECT_STREQ(attr->verified_by, "admin");
}

TEST_F(TestAttributeMachine, TestGenesisNullParams) {
  attribute_machine_t* null_am = attribute_machine_create(NULL, admin_pk);
  EXPECT_EQ(null_am, nullptr);

  uint8_t pk[33] = {0};
  null_am = attribute_machine_create("admin", NULL);
  EXPECT_EQ(null_am, nullptr);
}

TEST_F(TestAttributeMachine, TestRegisterUser) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);

  crabs_error_e result = attribute_machine_register_user(am, "alice", user_pk, "dept:eng|level:senior");
  EXPECT_EQ(result, CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_STREQ(alice->user_id, "alice");
  EXPECT_EQ(alice->status, USER_ACTIVE);
  EXPECT_EQ(alice->attribute_count, 2u);

  // Check first attribute: dept:eng
  EXPECT_STREQ(alice->attributes[0].value, "dept:eng");
  // Check second attribute: level:senior
  EXPECT_STREQ(alice->attributes[1].value, "level:senior");

  // Version should have incremented
  EXPECT_EQ(am->base_state.version, 2u);
  EXPECT_EQ(am->user_count, 2u);
}

TEST_F(TestAttributeMachine, TestRegisterUserNullAttrs) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);

  crabs_error_e result = attribute_machine_register_user(am, "bob", user_pk, NULL);
  EXPECT_EQ(result, CRABS_SUCCESS);

  user_t* bob = attribute_machine_find_user(am, "bob");
  ASSERT_NE(bob, nullptr);
  EXPECT_EQ(bob->attribute_count, 0u);
}

// R7-08: register_user must not mint privileged attributes (role, admin,
// owner, ...) from initial_attrs. Privileged attributes are granted only via
// the admin grant_role path; a public register_user call must not be able to
// create a role:admin user.
TEST_F(TestAttributeMachine, TestRegisterUserRejectsPrivilegedAttrs) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);

  crabs_error_e result = attribute_machine_register_user(am, "alice", user_pk, "role:admin");
  EXPECT_EQ(result, CRABS_ERR_INVALID_PARAM);

  // User must not have been created.
  EXPECT_EQ(attribute_machine_find_user(am, "alice"), nullptr);

  // Non-privileged attributes still work.
  result = attribute_machine_register_user(am, "bob", user_pk, "dept:eng|level:senior");
  EXPECT_EQ(result, CRABS_SUCCESS);
}

TEST_F(TestAttributeMachine, TestRegisterDuplicateUser) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);

  crabs_error_e result = attribute_machine_register_user(am, "alice", user_pk, "dept:eng");
  EXPECT_EQ(result, CRABS_SUCCESS);

  // Try registering same user_id again
  result = attribute_machine_register_user(am, "alice", user_pk, "dept:sales");
  EXPECT_EQ(result, CRABS_ERR_DUPLICATE_OPERATION);
}

TEST_F(TestAttributeMachine, TestRegisterUserNullParams) {
  uint8_t user_pk[33] = {0};
  EXPECT_EQ(attribute_machine_register_user(NULL, "alice", user_pk, NULL), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_register_user(am, NULL, user_pk, NULL), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_register_user(am, "alice", NULL, NULL), CRABS_ERR_INVALID_PARAM);
}

TEST_F(TestAttributeMachine, TestGrantRole) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  crabs_error_e result = attribute_machine_grant_role(am, "alice", "role", "editor", "admin");
  EXPECT_EQ(result, CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_TRUE(attribute_machine_user_has_role(alice, "role"));

  attribute_value_t* attr = attribute_machine_find_attribute(alice, "role");
  ASSERT_NE(attr, nullptr);
  EXPECT_STREQ(attr->value, "role:editor");
  EXPECT_STREQ(attr->verified_by, "admin");
}

TEST_F(TestAttributeMachine, TestGrantRoleUpdatesExisting) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  attribute_machine_grant_role(am, "alice", "role", "viewer", "admin");
  attribute_machine_grant_role(am, "alice", "role", "editor", "admin");

  user_t* alice = attribute_machine_find_user(am, "alice");
  EXPECT_EQ(alice->attribute_count, 1u);

  attribute_value_t* attr = attribute_machine_find_attribute(alice, "role");
  ASSERT_NE(attr, nullptr);
  EXPECT_STREQ(attr->value, "role:editor");
}

TEST_F(TestAttributeMachine, TestGrantRoleUserNotFound) {
  crabs_error_e result = attribute_machine_grant_role(am, "nonexistent", "role", "admin", "admin");
  EXPECT_EQ(result, CRABS_ERR_USER_NOT_FOUND);
}

TEST_F(TestAttributeMachine, TestGrantRoleSuspendedUser) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  attribute_machine_suspend_user(am, "alice");

  crabs_error_e result = attribute_machine_grant_role(am, "alice", "role", "editor", "admin");
  EXPECT_EQ(result, CRABS_ERR_USER_SUSPENDED);
}

TEST_F(TestAttributeMachine, TestRevokeRole) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  crabs_test_register_user_with_role(am, "alice", user_pk, "role", "editor");

  user_t* alice = attribute_machine_find_user(am, "alice");
  EXPECT_EQ(alice->attribute_count, 1u);
  EXPECT_TRUE(attribute_machine_user_has_role(alice, "role"));

  crabs_error_e result = attribute_machine_revoke_role(am, "alice", "role", "admin");
  EXPECT_EQ(result, CRABS_SUCCESS);

  // Refresh pointer (should still be valid)
  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->attribute_count, 0u);
  EXPECT_FALSE(attribute_machine_user_has_role(alice, "role"));
}

TEST_F(TestAttributeMachine, TestRevokeRoleNotFound) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  crabs_error_e result = attribute_machine_revoke_role(am, "alice", "nonexistent_role", "admin");
  EXPECT_EQ(result, CRABS_ERR_RESOURCE_NOT_FOUND);
}

TEST_F(TestAttributeMachine, TestRevokeRoleUserNotFound) {
  crabs_error_e result = attribute_machine_revoke_role(am, "nonexistent", "role", "admin");
  EXPECT_EQ(result, CRABS_ERR_USER_NOT_FOUND);
}

TEST_F(TestAttributeMachine, TestRevokeRoleShiftsAttributes) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, "dept:eng|level:senior");
  attribute_machine_grant_role(am, "alice", "role", "editor", "admin");

  user_t* alice = attribute_machine_find_user(am, "alice");
  EXPECT_EQ(alice->attribute_count, 3u);

  // Revoke "dept" which is in the middle
  crabs_error_e result = attribute_machine_revoke_role(am, "alice", "dept", "admin");
  EXPECT_EQ(result, CRABS_SUCCESS);

  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->attribute_count, 2u);

  // The remaining attributes should still be accessible
  EXPECT_TRUE(attribute_machine_user_has_role(alice, "role"));
  EXPECT_TRUE(attribute_machine_user_has_role(alice, "level"));
  EXPECT_FALSE(attribute_machine_user_has_role(alice, "dept"));
}

TEST_F(TestAttributeMachine, TestSelfAssert) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  crabs_error_e result = attribute_machine_self_assert(am, "email", "alice@example.com", "alice");
  EXPECT_EQ(result, CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->attribute_count, 1u);

  attribute_value_t* attr = attribute_machine_find_attribute(alice, "email");
  ASSERT_NE(attr, nullptr);
  EXPECT_STREQ(attr->value, "email:alice@example.com");
  // Self-asserted: verified_by should be empty
  EXPECT_STREQ(attr->verified_by, "");
}

TEST_F(TestAttributeMachine, TestSelfAssertUpdatesExisting) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  attribute_machine_self_assert(am, "email", "old@example.com", "alice");
  attribute_machine_self_assert(am, "email", "new@example.com", "alice");

  user_t* alice = attribute_machine_find_user(am, "alice");
  EXPECT_EQ(alice->attribute_count, 1u);

  attribute_value_t* attr = attribute_machine_find_attribute(alice, "email");
  ASSERT_NE(attr, nullptr);
  EXPECT_STREQ(attr->value, "email:new@example.com");
  EXPECT_STREQ(attr->verified_by, "");
}

TEST_F(TestAttributeMachine, TestSelfAssertUserNotFound) {
  crabs_error_e result = attribute_machine_self_assert(am, "email", "test@test.com", "nonexistent");
  EXPECT_EQ(result, CRABS_ERR_USER_NOT_FOUND);
}

TEST_F(TestAttributeMachine, TestSelfAssertSuspendedUser) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);
  attribute_machine_suspend_user(am, "alice");

  crabs_error_e result = attribute_machine_self_assert(am, "email", "test@test.com", "alice");
  EXPECT_EQ(result, CRABS_ERR_USER_SUSPENDED);
}

TEST_F(TestAttributeMachine, TestVerifyIdentity) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  // Admin verifies alice's identity
  crabs_error_e result = attribute_machine_verify_identity(am, "alice", "email", "alice@example.com", "admin");
  EXPECT_EQ(result, CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->attribute_count, 1u);

  attribute_value_t* attr = attribute_machine_find_attribute(alice, "email");
  ASSERT_NE(attr, nullptr);
  EXPECT_STREQ(attr->value, "email:alice@example.com");
  EXPECT_STREQ(attr->verified_by, "admin");
}

TEST_F(TestAttributeMachine, TestVerifyIdentityUpdatesExisting) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  // Alice self-asserts first
  attribute_machine_self_assert(am, "email", "alice@old.com", "alice");

  // Then admin verifies with updated value
  attribute_machine_verify_identity(am, "alice", "email", "alice@new.com", "admin");

  user_t* alice = attribute_machine_find_user(am, "alice");
  attribute_value_t* attr = attribute_machine_find_attribute(alice, "email");
  ASSERT_NE(attr, nullptr);
  EXPECT_STREQ(attr->value, "email:alice@new.com");
  EXPECT_STREQ(attr->verified_by, "admin");
}

TEST_F(TestAttributeMachine, TestVerifyIdentityUserNotFound) {
  crabs_error_e result = attribute_machine_verify_identity(am, "nonexistent", "email", "test@test.com", "admin");
  EXPECT_EQ(result, CRABS_ERR_USER_NOT_FOUND);
}

TEST_F(TestAttributeMachine, TestVerifyIdentitySuspendedUser) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);
  attribute_machine_suspend_user(am, "alice");

  crabs_error_e result = attribute_machine_verify_identity(am, "alice", "email", "test@test.com", "admin");
  EXPECT_EQ(result, CRABS_ERR_USER_SUSPENDED);
}

TEST_F(TestAttributeMachine, TestVerifyIdentityRejectsPrivilegedAttribute) {
  // R8-A-1: verify_identity must not mint privileged attributes (role:admin).
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  crabs_error_e result = attribute_machine_verify_identity(am, "alice", "role", "admin", "admin");
  EXPECT_EQ(result, CRABS_ERR_UNAUTHORIZED);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->attribute_count, 0u);
}

TEST_F(TestAttributeMachine, TestSuspendUser) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->status, USER_ACTIVE);

  crabs_error_e result = attribute_machine_suspend_user(am, "alice");
  EXPECT_EQ(result, CRABS_SUCCESS);

  // Refresh pointer
  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->status, USER_SUSPENDED);
}

TEST_F(TestAttributeMachine, TestSuspendUserNotFound) {
  crabs_error_e result = attribute_machine_suspend_user(am, "nonexistent");
  EXPECT_EQ(result, CRABS_ERR_USER_NOT_FOUND);
}

// R8-C-4: revocation is terminal. suspend_user must not downgrade a REVOKED
// user to the recoverable SUSPENDED state, or activate_user could resurrect
// a revoked user.
TEST_F(TestAttributeMachine, TestSuspendRevokedUserIsTerminal) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, NULL), CRABS_SUCCESS);
  ASSERT_EQ(attribute_machine_revoke_user(am, "alice"), CRABS_SUCCESS);

  crabs_error_e result = attribute_machine_suspend_user(am, "alice");
  EXPECT_NE(result, CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->status, USER_REVOKED);
}

// R7-07: crypto_revoke_and_rotate suspends the user during key-compromise
// recovery, but there was no reactivation path — the "recovery" was a
// permanent lockout. attribute_machine_activate_user restores a SUSPENDED
// user to ACTIVE under admin authorization.
TEST_F(TestAttributeMachine, TestActivateUser) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, NULL), CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  uint64_t version_before_suspend = alice->key_version;

  ASSERT_EQ(attribute_machine_suspend_user(am, "alice"), CRABS_SUCCESS);
  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->status, USER_SUSPENDED);
  uint64_t version_after_suspend = alice->key_version;
  EXPECT_EQ(version_after_suspend, version_before_suspend + 1);

  crabs_error_e result = attribute_machine_activate_user(am, "alice", "admin");
  EXPECT_EQ(result, CRABS_SUCCESS);

  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->status, USER_ACTIVE);
  // R8-A-5: key_version IS bumped by reactivation, so signatures made during
  // suspension at the old version are invalidated even if the key was not
  // rotated.
  EXPECT_EQ(alice->key_version, version_after_suspend + 1);
}

TEST_F(TestAttributeMachine, TestActivateUserRequiresAdmin) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, NULL), CRABS_SUCCESS);
  ASSERT_EQ(attribute_machine_suspend_user(am, "alice"), CRABS_SUCCESS);

  // bob has role:user, not role:admin — reactivation must be rejected.
  uint8_t bob_pk[33];
  _gen_pk(bob_pk);
  ASSERT_EQ(crabs_test_register_user_with_role(am, "bob", bob_pk, "role", "user"), CRABS_SUCCESS);

  crabs_error_e result = attribute_machine_activate_user(am, "alice", "bob");
  EXPECT_EQ(result, CRABS_ERR_UNAUTHORIZED);

  // alice stays suspended.
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->status, USER_SUSPENDED);
}

TEST_F(TestAttributeMachine, TestActivateUserNotFound) {
  crabs_error_e result = attribute_machine_activate_user(am, "nonexistent", "admin");
  EXPECT_EQ(result, CRABS_ERR_USER_NOT_FOUND);
}

TEST_F(TestAttributeMachine, TestActivateUserAlreadyActive) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, NULL), CRABS_SUCCESS);

  // An already-active user is not in a recoverable state.
  crabs_error_e result = attribute_machine_activate_user(am, "alice", "admin");
  EXPECT_EQ(result, CRABS_ERR_INVALID_PARAM);
}

TEST_F(TestAttributeMachine, TestActivateRevokedUserRejected) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, NULL), CRABS_SUCCESS);
  ASSERT_EQ(attribute_machine_revoke_user(am, "alice"), CRABS_SUCCESS);

  // Revocation is terminal (audit H-C): a REVOKED user cannot be reactivated.
  crabs_error_e result = attribute_machine_activate_user(am, "alice", "admin");
  EXPECT_EQ(result, CRABS_ERR_INVALID_PARAM);
}

// Regression for audit H-C: attribute_machine_revoke_user sets USER_REVOKED.
// Revocation is terminal — the enum value was previously declared but never
// assigned, so there was no way to actually revoke a user.
TEST_F(TestAttributeMachine, TestRevokeUser) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, NULL), CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->status, USER_ACTIVE);

  EXPECT_EQ(attribute_machine_revoke_user(am, "alice"), CRABS_SUCCESS);
  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->status, USER_REVOKED);
}

TEST_F(TestAttributeMachine, TestRevokeUserNotFound) {
  EXPECT_EQ(attribute_machine_revoke_user(am, "nonexistent"), CRABS_ERR_USER_NOT_FOUND);
}

// Regression for audit H-C: temp attributes with expires_at in the past are
// pruned once the platform injects a wall clock via attribute_machine_set_time.
// Without set_time, current_time_ms stays 0 and expired temp attrs are never
// pruned (they would grant authority indefinitely).
TEST_F(TestAttributeMachine, TestTempAttrExpiredAfterSetTime) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(crabs_test_register_user_with_role(am, "alice", user_pk, "role", "member"), CRABS_SUCCESS);

  // Issue a temp attribute with 5000ms duration at time 1000 → expires at 6000.
  // issue_temporary grants to users whose attribute NAME matches `role`; alice
  // has "role:member" so name "role" matches.
  attribute_machine_set_time(am, 1000);
  ASSERT_EQ(attribute_machine_issue_temporary(am, "clearance", "confidential", "role", 5000), CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->temp_attrs == NULL, false); // temp attr present

  // Advance time past expiry and prune.
  attribute_machine_set_time(am, 7000);
  uint32_t pruned = attribute_machine_prune_expired_temporary(am);
  EXPECT_GT(pruned, 0u);

  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->temp_attrs, nullptr); // expired temp attr removed
}

TEST_F(TestAttributeMachine, TestFindUser) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  user_t* found = attribute_machine_find_user(am, "alice");
  ASSERT_NE(found, nullptr);
  EXPECT_STREQ(found->user_id, "alice");

  user_t* not_found = attribute_machine_find_user(am, "bob");
  EXPECT_EQ(not_found, nullptr);
}

TEST_F(TestAttributeMachine, TestFindUserNullParams) {
  EXPECT_EQ(attribute_machine_find_user(NULL, "admin"), nullptr);
  EXPECT_EQ(attribute_machine_find_user(am, NULL), nullptr);
}

TEST_F(TestAttributeMachine, TestFindAttribute) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, "dept:eng|level:senior");

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);

  attribute_value_t* attr = attribute_machine_find_attribute(alice, "dept");
  ASSERT_NE(attr, nullptr);
  EXPECT_STREQ(attr->value, "dept:eng");

  attr = attribute_machine_find_attribute(alice, "level");
  ASSERT_NE(attr, nullptr);
  EXPECT_STREQ(attr->value, "level:senior");

  attr = attribute_machine_find_attribute(alice, "nonexistent");
  EXPECT_EQ(attr, nullptr);
}

TEST_F(TestAttributeMachine, TestFindAttributeNullParams) {
  uint8_t user_pk[33] = {0};
  crabs_test_register_user_with_role(am, "test", user_pk, "role", "test");
  user_t* user = attribute_machine_find_user(am, "test");

  EXPECT_EQ(attribute_machine_find_attribute(NULL, "role"), nullptr);
  EXPECT_EQ(attribute_machine_find_attribute(user, NULL), nullptr);
}

TEST_F(TestAttributeMachine, TestUserHasRole) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, "dept:eng");
  attribute_machine_grant_role(am, "alice", "role", "editor", "admin");

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);

  EXPECT_TRUE(attribute_machine_user_has_role(alice, "role"));
  EXPECT_TRUE(attribute_machine_user_has_role(alice, "dept"));
  EXPECT_FALSE(attribute_machine_user_has_role(alice, "admin"));
  EXPECT_FALSE(attribute_machine_user_has_role(alice, "nonexistent"));
}

TEST_F(TestAttributeMachine, TestUserHasRoleNullParams) {
  uint8_t user_pk[33] = {0};
  crabs_test_register_user_with_role(am, "test", user_pk, "role", "test");
  user_t* user = attribute_machine_find_user(am, "test");

  EXPECT_FALSE(attribute_machine_user_has_role(NULL, "role"));
  EXPECT_FALSE(attribute_machine_user_has_role(user, NULL));
}

TEST_F(TestAttributeMachine, TestIssueTemporaryAttribute) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, "dept:worker");

  am->current_time_ms = 1000;

  // Issue temporary attribute to users with "dept" attribute
  // Note: admin (with "role:admin") won't match "dept"
  crabs_error_e result = attribute_machine_issue_temporary(am, "clearance", "confidential", "dept", 5000);
  EXPECT_EQ(result, CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  ASSERT_NE(alice->temp_attrs, nullptr);

  temp_attr_list_t* temp = alice->temp_attrs;
  EXPECT_STREQ(temp->name, "clearance:confidential");
  EXPECT_STREQ(temp->value, "confidential");
  EXPECT_EQ(temp->issued_at, 1000u);
  EXPECT_EQ(temp->expires_at, 6000u);
}

TEST_F(TestAttributeMachine, TestIssueTemporarySkipsSuspendedUser) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, "dept:worker");
  attribute_machine_suspend_user(am, "alice");

  am->current_time_ms = 1000;

  crabs_error_e result = attribute_machine_issue_temporary(am, "clearance", "confidential", "dept", 5000);
  EXPECT_EQ(result, CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  // Suspended user should not receive temporary attributes
  EXPECT_EQ(alice->temp_attrs, nullptr);
}

TEST_F(TestAttributeMachine, TestIssueTemporaryNoMatchingUsers) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, "dept:eng");

  am->current_time_ms = 1000;

  // No user (other than admin) has "team:worker" attribute
  // Admin has "role:admin", so searching for "team" won't match admin either
  crabs_error_e result = attribute_machine_issue_temporary(am, "clearance", "confidential", "team", 5000);
  EXPECT_EQ(result, CRABS_SUCCESS);
}

TEST_F(TestAttributeMachine, TestIssueTemporaryZeroDuration) {
  crabs_error_e result = attribute_machine_issue_temporary(am, "clearance", "confidential", "role", 0);
  EXPECT_EQ(result, CRABS_ERR_INVALID_PARAM);
}

TEST_F(TestAttributeMachine, TestIssueTemporaryNullParams) {
  EXPECT_EQ(attribute_machine_issue_temporary(NULL, "a", "v", "r", 100), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_issue_temporary(am, NULL, "v", "r", 100), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_issue_temporary(am, "a", NULL, "r", 100), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_issue_temporary(am, "a", "v", NULL, 100), CRABS_ERR_INVALID_PARAM);
}

TEST_F(TestAttributeMachine, TestPruneExpiredTemporary) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, "dept:worker");

  am->current_time_ms = 1000;
  // Only alice has "dept" attribute (admin has "role")
  attribute_machine_issue_temporary(am, "clearance", "confidential", "dept", 5000);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  ASSERT_NE(alice->temp_attrs, nullptr);

  // Advance time past expiry
  am->current_time_ms = 7000;

  uint32_t pruned = attribute_machine_prune_expired_temporary(am);
  EXPECT_EQ(pruned, 1u);

  // Refresh pointer
  alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->temp_attrs, nullptr);
}

TEST_F(TestAttributeMachine, TestPruneExpiredTemporaryKeepsValid) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, "dept:worker");

  am->current_time_ms = 1000;
  attribute_machine_issue_temporary(am, "clearance", "confidential", "dept", 10000);

  // Advance time but not past expiry
  am->current_time_ms = 5000;

  uint32_t pruned = attribute_machine_prune_expired_temporary(am);
  EXPECT_EQ(pruned, 0u);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  ASSERT_NE(alice->temp_attrs, nullptr);
}

TEST_F(TestAttributeMachine, TestPruneExpiredTemporaryMultipleUsers) {
  uint8_t pk1[33], pk2[33];
  _gen_pk(pk1);
  _gen_pk(pk2);
  attribute_machine_register_user(am, "alice", pk1, "dept:worker");
  attribute_machine_register_user(am, "bob", pk2, "dept:worker");

  am->current_time_ms = 1000;
  // Only alice and bob have "dept" attribute (admin has "role")
  attribute_machine_issue_temporary(am, "clearance", "confidential", "dept", 5000);

  // Both users should have temp attrs
  user_t* alice = attribute_machine_find_user(am, "alice");
  user_t* bob = attribute_machine_find_user(am, "bob");
  ASSERT_NE(alice, nullptr);
  ASSERT_NE(bob, nullptr);
  EXPECT_NE(alice->temp_attrs, nullptr);
  EXPECT_NE(bob->temp_attrs, nullptr);

  // Advance time past expiry
  am->current_time_ms = 7000;
  uint32_t pruned = attribute_machine_prune_expired_temporary(am);
  EXPECT_EQ(pruned, 2u);

  // Both should have no temp attrs now
  alice = attribute_machine_find_user(am, "alice");
  bob = attribute_machine_find_user(am, "bob");
  EXPECT_EQ(alice->temp_attrs, nullptr);
  EXPECT_EQ(bob->temp_attrs, nullptr);
}

TEST_F(TestAttributeMachine, TestPruneExpiredNullMachine) {
  uint32_t pruned = attribute_machine_prune_expired_temporary(NULL);
  EXPECT_EQ(pruned, 0u);
}

TEST_F(TestAttributeMachine, TestPublicKeyStored) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(memcmp(alice->public_key, user_pk, 33), 0);
}

TEST_F(TestAttributeMachine, TestAdminPublicKeyStored) {
  user_t* admin = attribute_machine_find_user(am, "admin");
  ASSERT_NE(admin, nullptr);
  EXPECT_EQ(memcmp(admin->public_key, admin_pk, 33), 0);
}

TEST_F(TestAttributeMachine, TestVersionIncrements) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);

  uint64_t initial_version = am->base_state.version;

  attribute_machine_register_user(am, "alice", user_pk, NULL);
  EXPECT_EQ(am->base_state.version, initial_version + 1);

  attribute_machine_grant_role(am, "alice", "role", "editor", "admin");
  EXPECT_EQ(am->base_state.version, initial_version + 2);

  attribute_machine_self_assert(am, "email", "alice@test.com", "alice");
  EXPECT_EQ(am->base_state.version, initial_version + 3);

  attribute_machine_verify_identity(am, "alice", "email", "alice@test.com", "admin");
  EXPECT_EQ(am->base_state.version, initial_version + 4);

  attribute_machine_revoke_role(am, "alice", "email", "admin");
  EXPECT_EQ(am->base_state.version, initial_version + 5);

  attribute_machine_suspend_user(am, "alice");
  EXPECT_EQ(am->base_state.version, initial_version + 6);
}

TEST_F(TestAttributeMachine, TestKeyVersionIncrements) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  user_t* alice = attribute_machine_find_user(am, "alice");
  uint64_t initial_kv = alice->key_version;

  attribute_machine_grant_role(am, "alice", "role", "editor", "admin");
  alice = attribute_machine_find_user(am, "alice");
  EXPECT_EQ(alice->key_version, initial_kv + 1);

  attribute_machine_self_assert(am, "email", "a@a.com", "alice");
  alice = attribute_machine_find_user(am, "alice");
  EXPECT_EQ(alice->key_version, initial_kv + 2);
}

TEST_F(TestAttributeMachine, TestMaxAttributes) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  // Fill up to max attributes
  for (uint32_t i = 0; i < CRABS_MAX_ATTRIBUTES; i++) {
    char name[32];
    snprintf(name, sizeof(name), "attr%u", i);
    crabs_error_e result = attribute_machine_grant_role(am, "alice", name, "val", "admin");
    EXPECT_EQ(result, CRABS_SUCCESS);
  }

  // One more should fail
  crabs_error_e result = attribute_machine_grant_role(am, "alice", "overflow", "val", "admin");
  EXPECT_EQ(result, CRABS_ERR_INVARIANT_VIOLATED);
}

TEST_F(TestAttributeMachine, TestDestroyNull) {
  // Should not crash
  attribute_machine_destroy(NULL);
}
// Regression for audit C-5: a user must not be able to self-assert a
// privileged attribute (role:admin, admin, member, etc.) — those require an
// admin grant.
TEST_F(TestAttributeMachine, TestSelfAssertRejectsPrivileged) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, "dept:eng"), CRABS_SUCCESS);

  EXPECT_EQ(attribute_machine_self_assert(am, "role", "admin", "alice"),
            CRABS_ERR_UNAUTHORIZED);
  EXPECT_EQ(attribute_machine_self_assert(am, "admin", "true", "alice"),
            CRABS_ERR_UNAUTHORIZED);
  EXPECT_EQ(attribute_machine_self_assert(am, "member", "true", "alice"),
            CRABS_ERR_UNAUTHORIZED);

  // A non-privileged self-assert still works.
  EXPECT_EQ(attribute_machine_self_assert(am, "email", "alice@example.com", "alice"),
            CRABS_SUCCESS);
}

// Regression for audit F-1: a self-asserted attribute whose name is not
// privileged but whose value is a privileged word (e.g. clearance:admin) is
// stored as the whole token "clearance:admin". The end-to-end authorization
// regression (that this token does not satisfy "role:admin") lives in
// test_crypto.cpp's VerifyAuthTest.SelfAssertValueDoesNotAuthorize.
TEST_F(TestAttributeMachine, TestSelfAssertValueCollisionStoredNamespaced) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, "dept:eng"), CRABS_SUCCESS);

  ASSERT_EQ(attribute_machine_self_assert(am, "clearance", "admin", "alice"),
            CRABS_SUCCESS);

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  bool found = false;
  for (uint32_t i = 0; i < alice->attribute_count; i++) {
    if (strcmp(alice->attributes[i].value, "clearance:admin") == 0) found = true;
  }
  EXPECT_TRUE(found);
}

// ============================================================
// Round 4 audit regression tests
// ============================================================

// R4-2: a REVOKED user must be rejected by the direct API paths that
// previously only checked == USER_SUSPENDED. The H-C fix whitelisted
// USER_ACTIVE in the main authorization path but not in these direct APIs.
TEST_F(TestAttributeMachine, TestRevokedUserRejectedByDirectAPIs) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, "dept:eng"), CRABS_SUCCESS);

  // Revoke alice
  ASSERT_EQ(attribute_machine_revoke_user(am, "alice"), CRABS_SUCCESS);
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  EXPECT_EQ(alice->status, USER_REVOKED);

  // grant_role must reject a revoked target (previously let REVOKED through).
  EXPECT_EQ(attribute_machine_grant_role(am, "alice", "dept", "mgmt", "admin"),
            CRABS_ERR_USER_SUSPENDED);

  // self_assert must reject a revoked signer.
  EXPECT_EQ(attribute_machine_self_assert(am, "email", "a@b.com", "alice"),
            CRABS_ERR_USER_SUSPENDED);

  // verify_identity must reject a revoked target.
  EXPECT_EQ(attribute_machine_verify_identity(am, "alice", "dept", "eng", "admin"),
            CRABS_ERR_USER_SUSPENDED);
}

// R4-3: "verifier" and "issuer" must be in the privileged-attribute blocklist.
// A trigger with issue_attribute="verifier" must not mint a temp attribute.
TEST_F(TestAttributeMachine, TestPrivilegedAttrNamesIncludeVerifierIssuer) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(crabs_test_register_user_with_role(am, "alice", user_pk, "role", "staff"), CRABS_SUCCESS);

  // self_assert of "verifier" must be rejected.
  EXPECT_EQ(attribute_machine_self_assert(am, "verifier", "admin", "alice"),
            CRABS_ERR_UNAUTHORIZED);

  // self_assert of "issuer" must be rejected.
  EXPECT_EQ(attribute_machine_self_assert(am, "issuer", "admin", "alice"),
            CRABS_ERR_UNAUTHORIZED);

  // issue_temporary with attribute="verifier" must be rejected.
  attribute_machine_set_time(am, 1000);
  EXPECT_EQ(attribute_machine_issue_temporary(am, "verifier", "admin", "role:staff", 60000),
            CRABS_ERR_UNAUTHORIZED);
  EXPECT_EQ(attribute_machine_issue_temporary(am, "issuer", "admin", "role:staff", 60000),
            CRABS_ERR_UNAUTHORIZED);
}

// R4-5: attribute names outside [A-Za-z0-9_-] must be rejected so Unicode
// homoglyphs cannot bypass the case-insensitive privileged-name blocklist.
TEST_F(TestAttributeMachine, TestAttrNameCharsetValidation) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, "dept:eng"), CRABS_SUCCESS);

  // Non-ASCII / special chars in attribute name → rejected.
  EXPECT_EQ(attribute_machine_self_assert(am, "role admin", "true", "alice"),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_self_assert(am, "role;admin", "true", "alice"),
            CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(attribute_machine_self_assert(am, "role(admin)", "true", "alice"),
            CRABS_ERR_INVALID_PARAM);

  // issue_temporary with bad charset → rejected.
  attribute_machine_set_time(am, 1000);
  EXPECT_EQ(attribute_machine_issue_temporary(am, "bad name", "val", "role:staff", 60000),
            CRABS_ERR_INVALID_PARAM);

  // Valid charset still works.
  EXPECT_EQ(attribute_machine_self_assert(am, "clearance_level", "secret", "alice"),
            CRABS_SUCCESS);
}

// De-wonk: a comma in an attribute value would inject a separate token into
// the attribute string (which is comma-separated). self_assert("clearance",
// "secret,admin") would produce token "clearance:secret,admin", and the
// attribute string would contain "admin" as a separate token — satisfying a
// bare "admin" policy. Reject values containing commas or spaces.
TEST_F(TestAttributeMachine, TestAttrValueCommaInjectionRejected) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, "dept:eng"), CRABS_SUCCESS);

  // Comma in value → rejected (would inject "admin" as a separate token).
  EXPECT_EQ(attribute_machine_self_assert(am, "clearance", "secret,admin", "alice"),
            CRABS_ERR_INVALID_PARAM);

  // Space in value → rejected (would break policy token parsing).
  EXPECT_EQ(attribute_machine_self_assert(am, "clearance", "secret admin", "alice"),
            CRABS_ERR_INVALID_PARAM);

  // issue_temporary with comma in value → rejected.
  attribute_machine_set_time(am, 1000);
  EXPECT_EQ(attribute_machine_issue_temporary(am, "clearance", "secret,admin", "role", 60000),
            CRABS_ERR_INVALID_PARAM);

  // grant_role with comma in value → rejected.
  EXPECT_EQ(attribute_machine_grant_role(am, "alice", "dept", "secret,admin", "admin"),
            CRABS_ERR_INVALID_PARAM);

  // verify_identity with comma in value → rejected.
  EXPECT_EQ(attribute_machine_verify_identity(am, "alice", "dept", "eng,admin", "admin"),
            CRABS_ERR_INVALID_PARAM);

  // Normal value (no comma/space) still works.
  EXPECT_EQ(attribute_machine_self_assert(am, "clearance", "secret", "alice"),
            CRABS_SUCCESS);
}

// Audit R5-1: grant_role and verify_identity must validate the attribute NAME
// charset (not just the value). self_assert and issue_temporary call
// _is_safe_attr_name, but grant_role and verify_identity previously did not —
// a caller with grant/verify authority could pass a role name like
// "role,admin" which produces the token "role,admin:value", and the comma
// splits into two tokens in the attribute string ("role" and "admin:value"),
// letting a bare "role" token satisfy unrelated policies.
TEST_F(TestAttributeMachine, TestGrantRoleRejectsBadAttrNameCharset) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, "dept:eng"), CRABS_SUCCESS);

  // grant_role with comma in role NAME → rejected (would inject "admin" as a
  // separate token via the name part).
  EXPECT_EQ(attribute_machine_grant_role(am, "alice", "role,admin", "val", "admin"),
            CRABS_ERR_INVALID_PARAM);

  // grant_role with space in role NAME → rejected.
  EXPECT_EQ(attribute_machine_grant_role(am, "alice", "role admin", "val", "admin"),
            CRABS_ERR_INVALID_PARAM);

  // grant_role with parenthesis in role NAME → rejected.
  EXPECT_EQ(attribute_machine_grant_role(am, "alice", "role(admin)", "val", "admin"),
            CRABS_ERR_INVALID_PARAM);

  // grant_role with semicolon in role NAME → rejected.
  EXPECT_EQ(attribute_machine_grant_role(am, "alice", "role;admin", "val", "admin"),
            CRABS_ERR_INVALID_PARAM);

  // Valid charset still works.
  EXPECT_EQ(attribute_machine_grant_role(am, "alice", "clearance", "secret", "admin"),
            CRABS_SUCCESS);
}

TEST_F(TestAttributeMachine, TestVerifyIdentityRejectsBadAttrNameCharset) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, "dept:eng"), CRABS_SUCCESS);

  // verify_identity with comma in attribute NAME → rejected.
  EXPECT_EQ(attribute_machine_verify_identity(am, "alice", "email,admin", "val", "admin"),
            CRABS_ERR_INVALID_PARAM);

  // verify_identity with space in attribute NAME → rejected.
  EXPECT_EQ(attribute_machine_verify_identity(am, "alice", "email admin", "val", "admin"),
            CRABS_ERR_INVALID_PARAM);

  // verify_identity with parenthesis in attribute NAME → rejected.
  EXPECT_EQ(attribute_machine_verify_identity(am, "alice", "email(admin)", "val", "admin"),
            CRABS_ERR_INVALID_PARAM);

  // Valid charset still works.
  EXPECT_EQ(attribute_machine_verify_identity(am, "alice", "email", "alice@test.com", "admin"),
            CRABS_SUCCESS);
}

// Audit R5-2: _parse_attributes (used by register_user for initial attributes)
// must validate the name part of each "name:value" token against the safe
// charset. Previously it only checked for commas in the whole token (de-wonk)
// but did not validate the name part — a name like "role admin" (with a space)
// would be stored without rejection.
TEST_F(TestAttributeMachine, TestRegisterUserRejectsBadAttrNameInInitialAttrs) {
  uint8_t user_pk[33];
  _gen_pk(user_pk);

  // Initial attrs with a space in the name part → the malformed token is
  // skipped (not stored), so the user is registered with fewer attributes.
  ASSERT_EQ(attribute_machine_register_user(am, "alice", user_pk, "bad name:value|dept:eng"),
            CRABS_SUCCESS);
  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);
  // The "bad name:value" token is rejected; only "dept:eng" is stored.
  EXPECT_EQ(alice->attribute_count, 1u);
  EXPECT_STREQ(alice->attributes[0].value, "dept:eng");

  // Initial attrs with a comma in the name part → rejected by the de-wonk
  // comma check (the whole token contains a comma).
  uint8_t user_pk2[33];
  _gen_pk(user_pk2);
  ASSERT_EQ(attribute_machine_register_user(am, "bob", user_pk2, "role,admin:value"),
            CRABS_SUCCESS);
  user_t* bob = attribute_machine_find_user(am, "bob");
  ASSERT_NE(bob, nullptr);
  // The comma-containing token is rejected; bob has no attributes.
  EXPECT_EQ(bob->attribute_count, 0u);

  // Initial attrs with parenthesis in the name part → rejected by charset.
  uint8_t user_pk3[33];
  _gen_pk(user_pk3);
  ASSERT_EQ(attribute_machine_register_user(am, "carol", user_pk3, "name(attr):value|dept:eng"),
            CRABS_SUCCESS);
  user_t* carol = attribute_machine_find_user(am, "carol");
  ASSERT_NE(carol, nullptr);
  // The "name(attr):value" token is rejected; only "dept:eng" is stored.
  EXPECT_EQ(carol->attribute_count, 1u);
  EXPECT_STREQ(carol->attributes[0].value, "dept:eng");

  // Valid charset in all name parts → all attributes stored.
  uint8_t user_pk4[33];
  _gen_pk(user_pk4);
  ASSERT_EQ(attribute_machine_register_user(am, "dave", user_pk4, "dept:eng|clearance:secret"),
            CRABS_SUCCESS);
  ASSERT_EQ(attribute_machine_grant_role(am, "dave", "role", "staff", "admin"),
            CRABS_SUCCESS);
  user_t* dave = attribute_machine_find_user(am, "dave");
  ASSERT_NE(dave, nullptr);
  EXPECT_EQ(dave->attribute_count, 3u);
}
