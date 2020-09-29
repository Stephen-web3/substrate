// This file is part of Substrate.

// Copyright (C) 2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Functions to procedurally construct contract code used for benchmarking.
//!
//! In order to be able to benchmark events that are triggered by contract execution
//! (API calls into seal, individual instructions), we need to generate contracts that
//! perform those events. Because those contracts can get very big we cannot simply define
//! them as text (.wat) as this will be too slow and consume too much memory. Therefore
//! we define this simple definition of a contract that can be passed to `create_code` that
//! compiles it down into a `WasmModule` that can be used as a contract's code.

use crate::Trait;
use crate::Module as Contracts;

use parity_wasm::elements::{Instruction, Instructions, FuncBody, ValueType, BlockType};
use pwasm_utils::stack_height::inject_limiter;
use sp_runtime::traits::Hash;
use sp_sandbox::{EnvironmentDefinitionBuilder, Memory};
use sp_std::{prelude::*, convert::TryFrom};

/// Pass to `create_code` in order to create a compiled `WasmModule`.
#[derive(Default)]
pub struct ModuleDefinition {
	pub data_segments: Vec<DataSegment>,
	pub memory: Option<ImportedMemory>,
	pub imported_functions: Vec<ImportedFunction>,
	pub deploy_body: Option<FuncBody>,
	pub call_body: Option<FuncBody>,
	pub aux_body: Option<FuncBody>,
	/// If seto to true the stack height limiter is injected into the the module. This is
	/// needed for instruction debugging because the cost of executing the stack height
	/// instrumentation should be included in the costs for the individual instructions that cause
	/// more metering code (mainly call).
	pub inject_stack_metering: bool,
}

pub struct DataSegment {
	pub offset: u32,
	pub value: Vec<u8>,
}

#[derive(Clone)]
pub struct ImportedMemory {
	pub min_pages: u32,
	pub max_pages: u32,
}

impl ImportedMemory {
	pub fn max<T: Trait>() -> Self {
		let pages = max_pages::<T>();
		Self { min_pages: pages, max_pages: pages }
	}
}

pub struct ImportedFunction {
	pub name: &'static str,
	pub params: Vec<ValueType>,
	pub return_type: Option<ValueType>,
}

/// A wasm module ready to be put on chain with `put_code`.
#[derive(Clone)]
pub struct WasmModule<T:Trait> {
	pub code: Vec<u8>,
	pub hash: <T::Hashing as Hash>::Output,
	memory: Option<ImportedMemory>,
}

impl<T: Trait> From<ModuleDefinition> for WasmModule<T> {
	fn from(def: ModuleDefinition) -> Self {
		// internal functions start at that offset.
		let func_offset = u32::try_from(def.imported_functions.len()).unwrap();

		// Every contract must export "deploy" and "call" functions
		let mut contract = parity_wasm::builder::module()
			// deploy function (first internal function)
			.function()
				.signature().with_params(vec![]).with_return_type(None).build()
				.with_body(def.deploy_body.unwrap_or_else(||
					FuncBody::new(Vec::new(), Instructions::empty())
				))
				.build()
			// call function (second internal function)
			.function()
				.signature().with_params(vec![]).with_return_type(None).build()
				.with_body(def.call_body.unwrap_or_else(||
					FuncBody::new(Vec::new(), Instructions::empty())
				))
				.build()
			.export().field("deploy").internal().func(func_offset).build()
			.export().field("call").internal().func(func_offset + 1).build();

		// If specified we add an additional internal function
		if let Some(body) = def.aux_body {
			contract = contract
				.function()
				.signature().with_params(vec![]).with_return_type(None).build()
				.with_body(body)
				.build();
		}

		// Grant access to linear memory.
		if let Some(memory) = &def.memory {
			contract = contract.import()
				.module("env").field("memory")
				.external().memory(memory.min_pages, Some(memory.max_pages))
				.build();
		}

		// Import supervisor functions. They start with idx 0.
		for func in def.imported_functions {
			let sig = parity_wasm::builder::signature()
				.with_params(func.params)
				.with_return_type(func.return_type)
				.build_sig();
			let sig = contract.push_signature(sig);
			contract = contract.import()
				.module("seal0")
				.field(func.name)
				.with_external(parity_wasm::elements::External::Function(sig))
				.build();
		}

		// Initialize memory
		for data in def.data_segments {
			contract = contract.data()
				.offset(Instruction::I32Const(data.offset as i32))
				.value(data.value)
				.build()
		}

		let mut code = contract.build();
		if def.inject_stack_metering {
			code = inject_limiter(
				code,
				Contracts::<T>::current_schedule().limits.stack_height
			)
			.unwrap();
		}
		let code = code.to_bytes().unwrap();
		let hash = T::Hashing::hash(&code);
		Self {
			code,
			hash,
			memory: def.memory,
		}
	}
}

impl<T: Trait> WasmModule<T> {
	/// Creates a wasm module with an empty `call` and `deploy` function and nothing else.
	pub fn dummy() -> Self {
		ModuleDefinition::default().into()
	}

	/// Creates a wasm module of `target_bytes` size. Used to benchmark the performance of
	/// `put_code` for different sizes of wasm modules. The generated module maximizes
	/// instrumentation runtime by nesting blocks as deeply as possible given the byte budget.
	pub fn sized(target_bytes: u32) -> Self {
		use parity_wasm::elements::Instruction::{If, I32Const, Return, End};
		// Base size of a contract is 47 bytes and each expansion adds 6 bytes.
		// We do one expansion less to account for the code section and function body
		// size fields inside the binary wasm module representation which are leb128 encoded
		// and therefore grow in size when the contract grows. We are not allowed to overshoot
		// because of the maximum code size that is enforced by `put_code`.
		let expansions = (target_bytes.saturating_sub(47) / 6).saturating_sub(1);
		const EXPANSION: [Instruction; 4] = [
			I32Const(0),
			If(BlockType::NoResult),
			Return,
			End,
		];
		ModuleDefinition {
			call_body: Some(body::repeated(expansions, &EXPANSION)),
			.. Default::default()
		}
		.into()
	}

	/// Creates a wasm module that calls the imported function named `getter_name` `repeat`
	/// times. The imported function is expected to have the "getter signature" of
	/// (out_ptr: u32, len_ptr: u32) -> ().
	pub fn getter(getter_name: &'static str, repeat: u32) -> Self {
		let pages = max_pages::<T>();
		ModuleDefinition {
			memory: Some(ImportedMemory::max::<T>()),
			imported_functions: vec![ImportedFunction {
				name: getter_name,
				params: vec![ValueType::I32, ValueType::I32],
				return_type: None,
			}],
			// Write the output buffer size. The output size will be overwritten by the
			// supervisor with the real size when calling the getter. Since this size does not
			// change between calls it suffices to start with an initial value and then just
			// leave as whatever value was written there.
			data_segments: vec![DataSegment {
				offset: 0,
				value: (pages * 64 * 1024 - 4).to_le_bytes().to_vec(),
			}],
			call_body: Some(body::repeated(repeat, &[
				Instruction::I32Const(4), // ptr where to store output
				Instruction::I32Const(0), // ptr to length
				Instruction::Call(0), // call the imported function
			])),
			.. Default::default()
		}
		.into()
	}

	/// Creates a wasm module that calls the imported hash function named `name` `repeat` times
	/// with an input of size `data_size`. Hash functions have the signature
	/// (input_ptr: u32, input_len: u32, output_ptr: u32) -> ()
	pub fn hasher(name: &'static str, repeat: u32, data_size: u32) -> Self {
		ModuleDefinition {
			memory: Some(ImportedMemory::max::<T>()),
			imported_functions: vec![ImportedFunction {
				name: name,
				params: vec![ValueType::I32, ValueType::I32, ValueType::I32],
				return_type: None,
			}],
			call_body: Some(body::repeated(repeat, &[
				Instruction::I32Const(0), // input_ptr
				Instruction::I32Const(data_size as i32), // input_len
				Instruction::I32Const(0), // output_ptr
				Instruction::Call(0),
			])),
			.. Default::default()
		}
		.into()
	}

	/// Creates a memory instance for use in a sandbox with dimensions declared in this module
	/// and adds it to `env`. A reference to that memory is returned so that it can be used to
	/// access the memory contents from the supervisor.
	pub fn add_memory<S>(&self, env: &mut EnvironmentDefinitionBuilder<S>) -> Option<Memory> {
		let memory = if let Some(memory) = &self.memory {
			memory
		} else {
			return None;
		};
		let memory = Memory::new(memory.min_pages, Some(memory.max_pages)).unwrap();
		env.add_memory("env", "memory", memory.clone());
		Some(memory)
	}
}

/// Mechanisms to generate a function body that can be used inside a `ModuleDefinition`.
pub mod body {
	use super::*;

	/// When generating contract code by repeating a wasm sequence, it sometimes necessary
	/// to change those instructions on each repetition. The variants of this enum describe
	/// various ways in which this can happen.
	pub enum DynInstr {
		/// Insert the associated instruction.
		Regular(Instruction),
		/// Insert a I32Const with incrementing value for each insertion.
		/// (start_at, increment_by)
		Counter(u32, u32),
		/// Insert a I32Const with a random value in [low, high) not devisable by two.
		/// (low, high)
		RandomUnaligned(u32, u32),
		/// Insert a I32Const with a random value in [low, high).
		/// (low, high)
		RandomI32(i32, i32),
		/// Insert a I64Const with a random value in [low, high).
		/// (low, high)
		RandomI64(i64, i64),
	}

	pub fn plain(instructions: Vec<Instruction>) -> FuncBody {
		FuncBody::new(Vec::new(), Instructions::new(instructions))
	}

	pub fn repeated(repetitions: u32, instructions: &[Instruction]) -> FuncBody {
		let instructions = Instructions::new(
			instructions
				.iter()
				.cycle()
				.take(instructions.len() * usize::try_from(repetitions).unwrap())
				.cloned()
				.chain(sp_std::iter::once(Instruction::End))
				.collect()
		);
		FuncBody::new(Vec::new(), instructions)
	}

	pub fn repeated_dyn(repetitions: u32, mut instructions: Vec<DynInstr>) -> FuncBody {
		use rand::prelude::*;

		// We do not need to be secure here.
		let mut rng = SmallRng::seed_from_u64(8446744073709551615);

		// We need to iterate over indices because we cannot cycle over mutable references
		let body = (0..instructions.len())
			.cycle()
			.take(instructions.len() * usize::try_from(repetitions).unwrap())
			.map(|idx| {
				match &mut instructions[idx] {
					DynInstr::Regular(instruction) => instruction.clone(),
					DynInstr::Counter(offset, increment_by) => {
						let current = *offset;
						*offset += *increment_by;
						Instruction::I32Const(current as i32)
					},
					DynInstr::RandomUnaligned(low, high) => {
						let unaligned = rng.gen_range(*low, *high) | 1;
						Instruction::I32Const(unaligned as i32)
					},
					DynInstr::RandomI32(low, high) => {
						Instruction::I32Const(rng.gen_range(*low, *high))
					},
					DynInstr::RandomI64(low, high) => {
						Instruction::I64Const(rng.gen_range(*low, *high))
					},
				}
			})
			.chain(sp_std::iter::once(Instruction::End))
			.collect();
		FuncBody::new(Vec::new(), Instructions::new(body))
	}
}

/// The maximum amount of pages any contract is allowed to have according to the current `Schedule`.
pub fn max_pages<T: Trait>() -> u32 {
	Contracts::<T>::current_schedule().limits.memory_pages
}
