//
// Created by victor on 3/18/25.
//

#ifndef CRABS_THREADDING_H
#define CRABS_THREADDING_H

#include <stdint.h>
#include <pthread.h>

#define PLATFORMLOCKTYPE(N) pthread_mutex_t N
#define PLATFORMCONDITIONTYPE(N) pthread_cond_t N
#define PLATFORMCONDITIONTYPEPTR(N) pthread_cond_t* N
#define PLATFORMBARRIERTYPE(N) pthread_barrier_t N
#define PLATFORMTHREADTYPE pthread_t
#define PLATFORMRWLOCKTYPE(N) pthread_rwlock_t N

void platform_lock(pthread_mutex_t* lock);
void platform_unlock(pthread_mutex_t* lock);
void platform_rw_lock_r(pthread_rwlock_t* lock);
void platform_rw_lock_w(pthread_rwlock_t* lock);
void platform_rw_unlock_r(pthread_rwlock_t* lock);
void platform_rw_unlock_w(pthread_rwlock_t* lock);
void platform_lock_init(pthread_mutex_t* lock);
void platform_rw_lock_init(pthread_rwlock_t* lock);
void platform_lock_destroy(pthread_mutex_t* lock);
void platform_rw_lock_destroy(pthread_rwlock_t* lock);
void platform_condition_init(pthread_cond_t* condition);
void platform_condition_wait(pthread_mutex_t* lock, pthread_cond_t* condition);
void platform_condition_destroy(pthread_cond_t* condition);
void platform_signal_condition(pthread_cond_t* condition);
void platform_broadcast_condition(pthread_cond_t* condition);
void platform_barrier_init(pthread_barrier_t* barrier, unsigned int count);
int platform_barrier_wait(pthread_barrier_t* barrier);
void platform_barrier_destroy(pthread_barrier_t* barrier);
int platform_join(pthread_t thread);
int platform_core_count();
uint64_t platform_self();

#endif // CRABS_THREADDING_H
