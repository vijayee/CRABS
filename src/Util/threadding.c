//
// Created by victor on 3/18/25.
//
#include "threadding.h"
#include "log.h"
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

void platform_lock(pthread_mutex_t* lock) {
  int result = pthread_mutex_lock(lock);
  if (result) {
    log_trace("Failed to acquire lock");
    abort();
  }
}

void platform_rw_lock_r(pthread_rwlock_t* lock) {
  int result = pthread_rwlock_rdlock(lock);
  if (result) {
    log_trace("Failed to acquire rw lock");
    abort();
  }
}

void platform_rw_lock_w(pthread_rwlock_t* lock) {
  int result = pthread_rwlock_wrlock(lock);
  if (result) {
    log_trace("Failed to acquire rw lock");
    abort();
  }
}

void platform_unlock(pthread_mutex_t* lock) {
  int result = pthread_mutex_unlock(lock);
  if (result) {
    log_trace("Failed to release lock");
    abort();
  }
}

void platform_rw_unlock_r(pthread_rwlock_t* lock) {
  int result = pthread_rwlock_unlock(lock);
  if (result) {
    log_trace("Failed to release rw lock");
    abort();
  }
}

void platform_rw_unlock_w(pthread_rwlock_t* lock) {
  int result = pthread_rwlock_unlock(lock);
  if (result) {
    log_trace("Failed to release rw lock");
    abort();
  }
}

void platform_lock_init(pthread_mutex_t* lock) {
  int result = pthread_mutex_init(lock, NULL);
  if (result) {
    log_trace("Failed to initialize lock");
    abort();
  }
}

void platform_rw_lock_init(pthread_rwlock_t* lock) {
  int result = pthread_rwlock_init(lock, NULL);
  if (result) {
    log_trace("Failed to initialize RW lock");
    abort();
  }
}

void platform_lock_destroy(pthread_mutex_t* lock) {
  int result = pthread_mutex_destroy(lock);
  if (result) {
    log_trace("Failed to destroy lock");
    abort();
  }
}

void platform_rw_lock_destroy(pthread_rwlock_t* lock) {
  int result = pthread_rwlock_destroy(lock);
  if (result) {
    log_trace("Failed to destroy rw lock");
    abort();
  }
}

void platform_condition_init(pthread_cond_t* condition) {
  int result = pthread_cond_init(condition, NULL);
  if (result) {
    log_trace("Failed to initialize condition");
    abort();
  }
}

void platform_condition_wait(pthread_mutex_t* lock, pthread_cond_t* condition) {
  int result = pthread_cond_wait(condition, lock);
  if (result) {
    log_trace("Failed to wait on condition");
    abort();
  }
}

void platform_condition_destroy(pthread_cond_t* condition) {
  int result = pthread_cond_destroy(condition);
  if (result) {
    log_trace("Failed to destroy condition");
    abort();
  }
}

void platform_signal_condition(pthread_cond_t* condition) {
  int result = pthread_cond_signal(condition);
  if (result) {
    log_trace("Failed to signal condition");
    abort();
  }
}

void platform_broadcast_condition(pthread_cond_t* condition) {
  int result = pthread_cond_broadcast(condition);
  if (result) {
    log_trace("Failed to broadcast condition");
    abort();
  }
}

void platform_barrier_init(pthread_barrier_t* barrier, unsigned int count) {
  int result = pthread_barrier_init(barrier, NULL, count);
  if (result) {
    log_trace("Failed to initialize barrier");
    abort();
  }
}

int platform_barrier_wait(pthread_barrier_t* barrier) {
  return pthread_barrier_wait(barrier);
}

void platform_barrier_destroy(pthread_barrier_t* barrier) {
  int result = pthread_barrier_destroy(barrier);
  if (result) {
    log_trace("Failed to destroy barrier");
    abort();
  }
}

int platform_join(pthread_t thread) {
  return pthread_join(thread, NULL);
}

int platform_core_count() {
  return sysconf(_SC_NPROCESSORS_ONLN);
}

uint64_t platform_self() {
  return pthread_self();
}
