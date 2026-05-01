//
// Created by victor on 3/18/25.
//
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "buffer.h"
#include "../Util/allocator.h"

buffer_t* buffer_create(size_t size) {
  buffer_t* buf = get_clear_memory(sizeof(buffer_t));
  buf->data = get_clear_memory(size);
  buf->size = size;
  refcounter_init((refcounter_t*) buf);
  return buf;
}

buffer_t* buffer_create_from_pointer_copy(uint8_t* data, size_t size) {
  buffer_t* buf = get_clear_memory(sizeof(buffer_t));
  buf->size = size;
  buf->data = get_memory(size);
  buffer_copy_from_pointer(buf, data, size);
  refcounter_init((refcounter_t*) buf);
  return buf;
}

buffer_t* buffer_create_from_existing_memory(uint8_t* data, size_t size) {
  buffer_t* buf = get_clear_memory(sizeof(buffer_t));
  buf->data = data;
  buf->size = size;
  refcounter_init((refcounter_t*) buf);
  return buf;
}

buffer_t* buffer_copy(buffer_t* buf) {
  return buffer_create_from_pointer_copy(buf->data, buf->size);
}

buffer_t* buffer_concat(buffer_t* buf1, buffer_t* buf2) {
  buffer_t* buf = buffer_create(buf1->size + buf2->size);
  memcpy(buf->data, buf1->data, buf1->size);
  memcpy(buf->data + buf1->size, buf2->data, buf2->size);
  return buf;
}

void buffer_copy_from_pointer(buffer_t* buf, uint8_t* data, size_t size) {
  if (buf->size > size) {
    memcpy(buf->data, data, size);
  } else {
    memcpy(buf->data, data, buf->size);
  }
}

void buffer_destroy(buffer_t* buf) {
  refcounter_dereference((refcounter_t*)buf);
  if (refcounter_count((refcounter_t*)buf) == 0) {
    free(buf->data);
    refcounter_destroy_lock(&buf->refcounter);
    free(buf);
  }
}

uint8_t buffer_get_index(buffer_t* buf, size_t index) {
  return buf->data[index];
}

uint8_t buffer_set_index(buffer_t* buf, size_t index, uint8_t value) {
  return buf->data[index] = value;
}

buffer_t* buffer_slice(buffer_t* buf, size_t start, size_t end) {
  if (start > end || buf->size < end || buf->size < start) {
    return NULL;
  }
  uint8_t* startPtr = buf->data + start;
  size_t sliceSize = end - start;
  return buffer_create_from_pointer_copy(startPtr, sliceSize);
}

buffer_t* buffer_xor(buffer_t* buf1, buffer_t* buf2) {
  size_t size = buf1->size;
  if (buf2->size > buf1->size) {
    size = buf2->size;
  }
  size_t min = buf1->size;
  buffer_t* largest = buf2;
  if (buf2->size < buf1->size) {
    min = buf2->size;
    largest = buf1;
  }

  buffer_t* result = buffer_create(size);
  for (size_t i = 0; i < min; i++) {
    result->data[i] = buf1->data[i] ^ buf2->data[i];
  }
  for (size_t i = min; i < largest->size; i++) {
    result->data[i] = largest->data[i] ^ 0;
  }
  return result;
}

buffer_t* buffer_or(buffer_t* buf1, buffer_t* buf2) {
  size_t size = buf1->size;
  if (buf2->size > buf1->size) {
    size = buf2->size;
  }
  size_t min = buf1->size;
  buffer_t* largest = buf2;
  if (buf2->size < buf1->size) {
    min = buf2->size;
    largest = buf1;
  }

  buffer_t* result = buffer_create(size);
  for (size_t i = 0; i < min; i++) {
    result->data[i] = buf1->data[i] | buf2->data[i];
  }
  for (size_t i = min; i < largest->size; i++) {
    result->data[i] = largest->data[i] | 0;
  }
  return result;
}

buffer_t* buffer_and(buffer_t* buf1, buffer_t* buf2) {
  size_t size = buf1->size;
  if (buf2->size > buf1->size) {
    size = buf2->size;
  }
  size_t min = buf1->size;
  buffer_t* largest = buf2;
  if (buf2->size < buf1->size) {
    min = buf2->size;
    largest = buf1;
  }

  buffer_t* result = buffer_create(size);
  for (size_t i = 0; i < min; i++) {
    result->data[i] = buf1->data[i] & buf2->data[i];
  }
  for (size_t i = min; i < largest->size; i++) {
    result->data[i] = largest->data[i] & 0;
  }
  return result;
}

buffer_t* buffer_not(buffer_t* buf) {
  buffer_t* result = buffer_create(buf->size);
  for (size_t i = 0; i < buf->size; i++) {
    result->data[i] = !buf->data[i];
  }
  return result;
}

int8_t buffer_compare(buffer_t* buf1, buffer_t* buf2) {
  size_t length;
  if (buf2->size > buf1->size) {
    length = buf1->size;
  } else {
    length = buf2->size;
  }
  size_t a = buf1->size;
  size_t b = buf2->size;

  for (size_t i = 0; i < length; i++) {
    uint8_t val1 = buffer_get_index(buf1, i);
    uint8_t val2 = buffer_get_index(buf2, i);
    if (val1 != val2) {
      a = val1;
      b = val2;
    }
  }

  if (a > b) {
    return 1;
  } else if (b > a) {
    return -1;
  } else {
    return 0;
  }
}
