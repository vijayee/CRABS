#include <gtest/gtest.h>
extern "C" {
#include "../src/RefCounter/refcounter.h"
#include "../src/Buffer/buffer.h"
}

TEST(TestRefCounter, TestInitCount) {
  refcounter_t rc;
  refcounter_init(&rc);
  EXPECT_EQ(refcounter_count(&rc), 1);
}

TEST(TestRefCounter, TestReferenceIncrements) {
  refcounter_t rc;
  refcounter_init(&rc);
  refcounter_reference(&rc);
  EXPECT_EQ(refcounter_count(&rc), 2);
}

TEST(TestRefCounter, TestDereferenceDecrements) {
  refcounter_t rc;
  refcounter_init(&rc);
  refcounter_reference(&rc);
  EXPECT_EQ(refcounter_count(&rc), 2);
  refcounter_dereference(&rc);
  EXPECT_EQ(refcounter_count(&rc), 1);
}

TEST(TestRefCounter, TestDereferenceToZero) {
  refcounter_t rc;
  refcounter_init(&rc);
  refcounter_dereference(&rc);
  EXPECT_EQ(refcounter_count(&rc), 0);
}

TEST(TestRefCounter, TestYieldConsume) {
  refcounter_t rc;
  refcounter_init(&rc);
  refcounter_yield(&rc);
  // After yield, reference should consume the yield, not increment
  refcounter_reference(&rc);
  EXPECT_EQ(refcounter_count(&rc), 1);
}

TEST(TestRefCounter, TestConsumeMacro) {
  refcounter_t rc;
  refcounter_init(&rc);
  refcounter_t* ptr = &rc;
  refcounter_t* consumed = refcounter_consume(&ptr);
  EXPECT_EQ(ptr, nullptr);
  EXPECT_EQ(consumed, &rc);
}

TEST(TestBuffer, TestBufferCreation) {
  buffer_t* buf = buffer_create(25);
  ASSERT_NE(buf, nullptr);
  ASSERT_NE(buf->data, nullptr);
  EXPECT_EQ(buf->size, 25);
  // Should be zero-initialized
  for (size_t i = 0; i < buf->size; i++) {
    EXPECT_EQ(buffer_get_index(buf, i), 0);
  }
  buffer_destroy(buf);
}

TEST(TestBuffer, TestBufferCreateFromPointerCopy) {
  uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
  buffer_t* buf = buffer_create_from_pointer_copy(data, 5);
  ASSERT_NE(buf, nullptr);
  EXPECT_EQ(buf->size, 5);
  for (size_t i = 0; i < buf->size; i++) {
    EXPECT_EQ(buffer_get_index(buf, i), data[i]);
  }
  buffer_destroy(buf);
}

TEST(TestBuffer, TestBufferCopy) {
  uint8_t data[] = {0x01, 0x02, 0x03};
  buffer_t* orig = buffer_create_from_pointer_copy(data, 3);
  buffer_t* copy = buffer_copy(orig);
  ASSERT_NE(copy, nullptr);
  EXPECT_EQ(copy->size, orig->size);
  EXPECT_NE(copy->data, orig->data); // Different memory
  for (size_t i = 0; i < copy->size; i++) {
    EXPECT_EQ(buffer_get_index(copy, i), buffer_get_index(orig, i));
  }
  buffer_destroy(orig);
  buffer_destroy(copy);
}

TEST(TestBuffer, TestBufferConcat) {
  uint8_t d1[] = {0x01, 0x02};
  uint8_t d2[] = {0x03, 0x04, 0x05};
  buffer_t* b1 = buffer_create_from_pointer_copy(d1, 2);
  buffer_t* b2 = buffer_create_from_pointer_copy(d2, 3);
  buffer_t* concat = buffer_concat(b1, b2);
  ASSERT_NE(concat, nullptr);
  EXPECT_EQ(concat->size, 5);
  EXPECT_EQ(buffer_get_index(concat, 0), 0x01);
  EXPECT_EQ(buffer_get_index(concat, 1), 0x02);
  EXPECT_EQ(buffer_get_index(concat, 2), 0x03);
  EXPECT_EQ(buffer_get_index(concat, 3), 0x04);
  EXPECT_EQ(buffer_get_index(concat, 4), 0x05);
  buffer_destroy(b1);
  buffer_destroy(b2);
  buffer_destroy(concat);
}

TEST(TestBuffer, TestBufferSlice) {
  uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
  buffer_t* buf = buffer_create_from_pointer_copy(data, 5);
  buffer_t* slice = buffer_slice(buf, 1, 4);
  ASSERT_NE(slice, nullptr);
  EXPECT_EQ(slice->size, 3);
  EXPECT_EQ(buffer_get_index(slice, 0), 0x02);
  EXPECT_EQ(buffer_get_index(slice, 1), 0x03);
  EXPECT_EQ(buffer_get_index(slice, 2), 0x04);
  buffer_destroy(buf);
  buffer_destroy(slice);
}

TEST(TestBuffer, TestBufferXor) {
  uint8_t d1[] = {0xFF, 0x00, 0x0F};
  uint8_t d2[] = {0x00, 0xFF, 0x0F};
  buffer_t* b1 = buffer_create_from_pointer_copy(d1, 3);
  buffer_t* b2 = buffer_create_from_pointer_copy(d2, 3);
  buffer_t* x = buffer_xor(b1, b2);
  ASSERT_NE(x, nullptr);
  EXPECT_EQ(buffer_get_index(x, 0), 0xFF);
  EXPECT_EQ(buffer_get_index(x, 1), 0xFF);
  EXPECT_EQ(buffer_get_index(x, 2), 0x00);
  buffer_destroy(b1);
  buffer_destroy(b2);
  buffer_destroy(x);
}

TEST(TestBuffer, TestBufferCompare) {
  uint8_t d1[] = {0x01, 0x02, 0x03};
  uint8_t d2[] = {0x01, 0x02, 0x03};
  uint8_t d3[] = {0x01, 0x02, 0x04};
  buffer_t* b1 = buffer_create_from_pointer_copy(d1, 3);
  buffer_t* b2 = buffer_create_from_pointer_copy(d2, 3);
  buffer_t* b3 = buffer_create_from_pointer_copy(d3, 3);
  EXPECT_EQ(buffer_compare(b1, b2), 0);
  EXPECT_NE(buffer_compare(b1, b3), 0);
  buffer_destroy(b1);
  buffer_destroy(b2);
  buffer_destroy(b3);
}
