/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_mem_module.h — Memory collection module public declaration.
 */

#ifndef AE_MEM_MODULE_H
#define AE_MEM_MODULE_H

#include "../core/ae_module_registry.h"

/* Statically-initialised CollectionModule for memory tiers.
 * Register with ae_registry_register(&mem_collection_module) in ae_main.c. */
extern const CollectionModule mem_collection_module;

#endif /* AE_MEM_MODULE_H */
