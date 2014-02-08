/*
 * upstream.h
 *
 *  Created on: Feb 7, 2014
 *      Author: cebka
 */

#ifndef UPSTREAM_H_
#define UPSTREAM_H_

#include <time.h>

/**
 * @file upstream.h
 * The basic macros to define upstream objects
 */

typedef struct upstream_entry_s {
	unsigned short errors;						/**< Errors for this upstream 	*/
	unsigned short dead;
	unsigned short priority;
	unsigned short weight;
	time_t time;						/**< Time of marking 			*/
} upstream_entry_t;

/*
 * Here we define some reasonable defaults:
 * if an upstream has more than `UPSTREAM_MAX_ERRORS` in the period of time
 * of `UPSTREAM_ERROR_TIME` then we shut it down for `UPSTREAM_REVIVE_TIME`.
 * In this particular case times are 10 seconds for 10 errors and revive in
 * 30 seconds.
 */
#define UPSTREAM_REVIVE_TIME 30
#define UPSTREAM_ERROR_TIME 10
#define UPSTREAM_MAX_ERRORS 10

#define UPSTREAM_FAIL(u, now) do {											\
	if ((u)->up.time != 0) {												\
		(u)->up.errors ++;													\
	}																		\
	else {																	\
		(u)->up.time = now;													\
		(u)->dead = 1;														\
	}																		\
} while (0)

#define UPSTREAM_OK(u) do {													\
	(u)->up.errors = 0;														\
} while (0)

#define UPSTREAM_REVIVE_ALL(u, next) do {									\
	__typeof(u) elt = (u);													\
	while (elt != NULL) {													\
		elt->up.dead = 0;													\
		elt->up.errors = 0;													\
		elt = elt->(next);													\
	}																		\
} while (0)

#define UPSTREAM_RESCAN(u, next, now) do {									\
	__typeof(u) elt = (u);													\
	int alive = 0;															\
	while (elt != NULL) {													\
		if (elt->up.dead) {													\
			if ((now) - elt->up.time >= UPSTREAM_REVIVE_TIME) {				\
				elt->up.dead = 0;											\
				elt->up.errors = 0;											\
				elt->up.weight = elt->up.priority;							\
				alive ++;													\
			}																\
		}																	\
		else {																\
			if ((now) - elt->up.time >= UPSTREAM_ERROR_TIME &&				\
					elt->up.errors >= UPSTREAM_MAX_ERRORS) {				\
				elt->up.dead = 1;											\
				elt->up.time = now;											\
			}																\
			else {															\
				alive ++;													\
			}																\
		}																	\
		elt = elt->(next);													\
	}																		\
	if (alive == 0) {														\
		UPSTREAM_REVIVE_ALL((u), (next));									\
	}																		\
} while (0)

#define UPSTREAM_SELECT_ROUND_ROBIN(u, next, selected) do {					\
	__typeof(u) elt = (u);													\
	selected = NULL;														\
	int alive = 0;															\
	unsigned max_weight = 0;												\
	upstream_round_robin_again:												\
	while (elt != NULL) {													\
		if (!elt->dead) {													\
			if (elt->up.weight > max_weight) {								\
				max_weight = elt->up.weight;								\
				selected = elt;												\
			}																\
			alive ++;														\
		}																	\
		elt = elt->(next);													\
	}																		\
	if (alive == 0) {														\
		UPSTREAM_REVIVE_ALL((u), (next));									\
		goto upstream_round_robin_again;									\
	}																		\
	else if (max_weight == 0) {												\
		elt = (u);															\
		while (elt != NULL) {												\
			if (!elt->dead) {												\
				if (elt->up.priority > max_weight) {						\
					max_weight = elt->up.priority;							\
					selected = elt;											\
				}															\
			}																\
			elt = elt->(next);												\
		}																	\
	}																		\
} while (0)

#endif /* UPSTREAM_H_ */
