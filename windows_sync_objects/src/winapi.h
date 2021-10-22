/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#include <cstdint>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) < 0x80000000)

namespace {
const std::uint32_t OBJ_CASE_INSENSITIVE = 0x00000040L;
const std::uint32_t DIRECTORY_QUERY = 0x0001;
const std::uint32_t DIRECTORY_TRAVERSE = 0x0002;
const std::uint32_t STATUS_MORE_ENTRIES = 0x00000105L;
const std::uint32_t EVENT_QUERY_STATE = 0x00000001L;
const std::uint32_t SEMAPHORE_QUERY_STATE = 0x00000001L;

enum OBJECT_INFORMATION_CLASS { ObjectBasicInformation, ObjectTypeInformation };
enum EVENT_INFORMATION_CLASS { EventBasicInformation };
enum EVENT_TYPE { NotificationEvent, SynchronizationEvent };
enum MUTANT_INFORMATION_CLASS { MutantBasicInformation };
enum SEMAPHORE_INFORMATION_CLASS { SemaphoreBasicInformation };

using NTSTATUS = ULONG;

struct UNICODE_STRING final {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
};

struct OBJECT_ATTRIBUTES final {
  ULONG Length;
  HANDLE RootDirectory;
  UNICODE_STRING* ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
};

struct OBJECT_DIRECTORY_INFORMATION final {
  UNICODE_STRING Name;
  UNICODE_STRING TypeName;
};

struct OBJECT_BASIC_INFORMATION final {
  ULONG Attributes;
  ACCESS_MASK DesiredAccess;
  ULONG HandleCount;
  ULONG ReferenceCount;
  ULONG PagedPoolUsage;
  ULONG NonPagedPoolUsage;
  ULONG Reserved[3];
  ULONG NameInformationLength;
  ULONG TypeInformationLength;
  ULONG SecurityDescriptorLength;
  LARGE_INTEGER CreationTime;
};

struct EVENT_BASIC_INFORMATION final {
  EVENT_TYPE EventType;
  LONG EventState;
};

struct MUTANT_BASIC_INFORMATION final {
  LONG CurrentCount;
  BOOLEAN OwnedByCaller;
  BOOLEAN AbandonedState;
};

struct SEMAPHORE_BASIC_INFORMATION final {
  ULONG CurrentCount;
  ULONG MaximumCount;
};

// clang-format off
#define InitializeObjectAttributes(p,n,a,r,s) { \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
  (p)->RootDirectory = (r); \
  (p)->Attributes = (a); \
  (p)->ObjectName = (n); \
  (p)->SecurityDescriptor = (s); \
  (p)->SecurityQualityOfService = NULL; \
}

#define ReleaseHandle(handle) \
  while (handle != nullptr) { \
    CloseHandle(handle); \
    handle = nullptr; \
  }

#ifndef NT_ERROR
#define NT_ERROR(Status) (((NTSTATUS)(Status)) >= (unsigned long)0xc0000000)
#endif
// clang-format on

extern "C" NTSYSCALLAPI void WINAPI
RtlInitUnicodeString(UNICODE_STRING* DestinationString, PCWSTR SourceString);

extern "C" NTSYSCALLAPI NTSTATUS WINAPI
NtOpenDirectoryObject(PHANDLE DirectoryHandle,
                      ACCESS_MASK DesiredAccess,
                      OBJECT_ATTRIBUTES* ObjectAttributes);

extern "C" NTSYSCALLAPI NTSTATUS WINAPI
NtQueryDirectoryObject(HANDLE DirectoryHandle,
                       PVOID Buffer,
                       ULONG Length,
                       BOOLEAN ReturnSingleEntry,
                       BOOLEAN RestartScan,
                       PULONG Context,
                       PULONG ReturnLength);

extern "C" NTSYSCALLAPI NTSTATUS WINAPI
NtQueryObject(HANDLE Object,
              OBJECT_INFORMATION_CLASS ObjectInfoClass,
              PVOID Buffer,
              ULONG BufferSize,
              PULONG BytesReturned);

extern "C" NTSYSCALLAPI ULONG WINAPI RtlNtStatusToDosError(NTSTATUS Status);

extern "C" NTSYSCALLAPI NTSTATUS NTAPI
NtOpenEvent(PHANDLE EventHandle,
            ACCESS_MASK DesiredAccess,
            OBJECT_ATTRIBUTES* ObjectAttributes);

extern "C" NTSYSCALLAPI NTSTATUS NTAPI
NtQueryEvent(HANDLE EventHandle,
             EVENT_INFORMATION_CLASS EventInformationClass,
             PVOID EventInformation,
             ULONG EventInformationLength,
             PULONG ReturnLength);

extern "C" NTSYSCALLAPI NTSTATUS NTAPI
NtOpenMutant(PHANDLE MutantHandle,
             ACCESS_MASK DesiredAccess,
             OBJECT_ATTRIBUTES* ObjectAttributes);

extern "C" NTSYSCALLAPI NTSTATUS NTAPI
NtQueryMutant(HANDLE MutantHandle,
              MUTANT_INFORMATION_CLASS MutantInformationClass,
              PVOID MutantInformation,
              ULONG MutantInformationLength,
              PULONG ResultLength);

extern "C" NTSYSCALLAPI NTSTATUS NTAPI
NtOpenSemaphore(PHANDLE SemaphoreHandle,
                ACCESS_MASK DesiredAccess,
                OBJECT_ATTRIBUTES* ObjectAttributes);

extern "C" NTSYSCALLAPI NTSTATUS NTAPI
NtQuerySemaphore(HANDLE SemaphoreHandle,
                 SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
                 PVOID SemaphoreInformation,
                 ULONG SemaphoreInformationLength,
                 PULONG ReturnLength);

extern "C" NTSYSCALLAPI NTSTATUS NTAPI
NtCreateMutant(HANDLE* MutantHandle,
               ACCESS_MASK DesiredAccess,
               OBJECT_ATTRIBUTES* ObjectAttributes,
               BOOLEAN InitialOwner);

extern "C" NTSYSCALLAPI NTSTATUS NTAPI
NtCreateEvent(HANDLE* EventHandle,
              ACCESS_MASK DesiredAccess,
              OBJECT_ATTRIBUTES* ObjectAttributes,
              EVENT_TYPE EventType,
              BOOLEAN InitialState);

extern "C" NTSYSCALLAPI NTSTATUS NTAPI
NtCreateSemaphore(HANDLE* SemaphoreHandle,
                  ACCESS_MASK DesiredAccess,
                  OBJECT_ATTRIBUTES* ObjectAttributes,
                  ULONG InitialCount,
                  ULONG MaximumCount);
} // namespace
