#include <gtest/gtest.h>
extern "C" {
#include "../src/Attribute/attribute_machine.h"
}

class TestAttributeMachine : public ::testing::Test {
protected:
  attribute_machine_t* am;
  uint8_t admin_pk[33];

  void SetUp() override {
    memset(admin_pk, 0xAB, 33);
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
  memset(user_pk, 0xCD, 33);

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
  memset(user_pk, 0xEE, 33);

  crabs_error_e result = attribute_machine_register_user(am, "bob", user_pk, NULL);
  EXPECT_EQ(result, CRABS_SUCCESS);

  user_t* bob = attribute_machine_find_user(am, "bob");
  ASSERT_NE(bob, nullptr);
  EXPECT_EQ(bob->attribute_count, 0u);
}

TEST_F(TestAttributeMachine, TestRegisterDuplicateUser) {
  uint8_t user_pk[33];
  memset(user_pk, 0xCD, 33);

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
  memset(user_pk, 0xCD, 33);
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
  memset(user_pk, 0xCD, 33);
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
  memset(user_pk, 0xCD, 33);
  attribute_machine_register_user(am, "alice", user_pk, NULL);

  attribute_machine_suspend_user(am, "alice");

  crabs_error_e result = attribute_machine_grant_role(am, "alice", "role", "editor", "admin");
  EXPECT_EQ(result, CRABS_ERR_USER_SUSPENDED);
}

TEST_F(TestAttributeMachine, TestRevokeRole) {
  uint8_t user_pk[33];
  memset(user_pk, 0xCD, 33);
  attribute_machine_register_user(am, "alice", user_pk, "role:editor");

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
  memset(user_pk, 0xCD, 33);
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
  memset(user_pk, 0xCD, 33);
  attribute_machine_register_user(am, "alice", user_pk, "role:editor|dept:eng|level:senior");

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
  memset(user_pk, 0xCD, 33);
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
  memset(user_pk, 0xCD, 33);
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
  memset(user_pk, 0xCD, 33);
  attribute_machine_register_user(am, "alice", user_pk, NULL);
  attribute_machine_suspend_user(am, "alice");

  crabs_error_e result = attribute_machine_self_assert(am, "email", "test@test.com", "alice");
  EXPECT_EQ(result, CRABS_ERR_USER_SUSPENDED);
}

TEST_F(TestAttributeMachine, TestVerifyIdentity) {
  uint8_t user_pk[33];
  memset(user_pk, 0xCD, 33);
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
  memset(user_pk, 0xCD, 33);
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
  memset(user_pk, 0xCD, 33);
  attribute_machine_register_user(am, "alice", user_pk, NULL);
  attribute_machine_suspend_user(am, "alice");

  crabs_error_e result = attribute_machine_verify_identity(am, "alice", "email", "test@test.com", "admin");
  EXPECT_EQ(result, CRABS_ERR_USER_SUSPENDED);
}

TEST_F(TestAttributeMachine, TestSuspendUser) {
  uint8_t user_pk[33];
  memset(user_pk, 0xCD, 33);
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

TEST_F(TestAttributeMachine, TestFindUser) {
  uint8_t user_pk[33];
  memset(user_pk, 0xCD, 33);
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
  memset(user_pk, 0xCD, 33);
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
  attribute_machine_register_user(am, "test", user_pk, "role:test");
  user_t* user = attribute_machine_find_user(am, "test");

  EXPECT_EQ(attribute_machine_find_attribute(NULL, "role"), nullptr);
  EXPECT_EQ(attribute_machine_find_attribute(user, NULL), nullptr);
}

TEST_F(TestAttributeMachine, TestUserHasRole) {
  uint8_t user_pk[33];
  memset(user_pk, 0xCD, 33);
  attribute_machine_register_user(am, "alice", user_pk, "role:editor|dept:eng");

  user_t* alice = attribute_machine_find_user(am, "alice");
  ASSERT_NE(alice, nullptr);

  EXPECT_TRUE(attribute_machine_user_has_role(alice, "role"));
  EXPECT_TRUE(attribute_machine_user_has_role(alice, "dept"));
  EXPECT_FALSE(attribute_machine_user_has_role(alice, "admin"));
  EXPECT_FALSE(attribute_machine_user_has_role(alice, "nonexistent"));
}

TEST_F(TestAttributeMachine, TestUserHasRoleNullParams) {
  uint8_t user_pk[33] = {0};
  attribute_machine_register_user(am, "test", user_pk, "role:test");
  user_t* user = attribute_machine_find_user(am, "test");

  EXPECT_FALSE(attribute_machine_user_has_role(NULL, "role"));
  EXPECT_FALSE(attribute_machine_user_has_role(user, NULL));
}

TEST_F(TestAttributeMachine, TestIssueTemporaryAttribute) {
  uint8_t user_pk[33];
  memset(user_pk, 0xCD, 33);
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
  memset(user_pk, 0xCD, 33);
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
  memset(user_pk, 0xCD, 33);
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
  memset(user_pk, 0xCD, 33);
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
  memset(user_pk, 0xCD, 33);
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
  memset(pk1, 0xCD, 33);
  memset(pk2, 0xEF, 33);
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
  memset(user_pk, 0xCD, 33);
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
  memset(user_pk, 0xCD, 33);

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
  memset(user_pk, 0xCD, 33);
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
  memset(user_pk, 0xCD, 33);
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