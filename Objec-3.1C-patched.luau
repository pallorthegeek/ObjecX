-- Objec 3.1C - Executor Isolation & Anti-Cheat Bypass System
-- Provides context-aware execution environment with layered metatable protection
-- Isolates executor scripts from game scripts while maintaining compatibility

-- Core Dependencies Backup
-- Store original references to prevent hook interference
local selfPrint = print
local selfWarn = warn
local selfGame = game
local selfTick = tick
local selfOsTime = os.time

-- Bitwise Operations
local selfBit32Bxor = bit32.bxor
local selfBit32Band = bit32.band
local selfBit32Bnot = bit32.bnot
local selfBit32Rrotate = bit32.rrotate
local selfBit32Rshift = bit32.rshift
local selfBit32Lshift = bit32.lshift
local selfBit32Bor = bit32.bor

-- String Manipulation
local selfStringChar = string.char
local selfStringRep = string.rep
local selfStringByte = string.byte
local selfStringSub = string.sub
local selfStringFormat = string.format
local selfStringMatch = string.match
local selfStringGmatch = string.gmatch
local selfStringGsub = string.gsub
local selfStringLen = string.len
local selfStringFind = string.find
local selfStringLower = string.lower

-- Table Operations
local selfTableInsert = table.insert
local selfTableConcat = table.concat
local selfTableRemove = table.remove
local selfTableUnpack = table.unpack or unpack

-- Math Functions
local selfMathFloor = math.floor
local selfMathMax = math.max
local selfMathMin = math.min

-- Type Checking & Metamethods
local selfType = type
local selfTonumber = tonumber
local selfTostring = tostring
local selfPairs = pairs
local selfIpairs = ipairs
local selfNext = next
local selfSetmetatable = setmetatable
local selfGetmetatable = getmetatable
local selfRawget = rawget
local selfRawset = rawset
local selfRawequal = rawequal
local selfSelect = select

-- Error Handling
local selfPcall = pcall
local selfError = error
local selfAssert = assert

-- Coroutine Management
local selfCoroutineWrap = coroutine.wrap
local selfCoroutineCreate = coroutine.create
local selfCoroutineRunning = coroutine.running
local selfCoroutineYield = coroutine.yield
local selfCoroutineResume = coroutine.resume
local selfCoroutineStatus = coroutine.status

-- Code Execution
local selfLoadstring = loadstring
local selfRequire = require

-- Task Scheduling
local selfTaskSpawn = task.spawn
local selfTaskDefer = task.defer
local selfTaskDelay = task.delay
local selfTaskWait = task.wait

-- Exploit Functions
local selfCheckcaller = checkcaller
local selfIslclosure = islclosure
local selfIscclosure = iscclosure
local selfGetgc = getgc
local selfGetloadedmodules = getloadedmodules
local selfNewcclosure = newcclosure
local selfGetrawmetatable = getrawmetatable
local selfSetreadonly = setreadonly
local selfGetnamecallmethod = getnamecallmethod
local selfHookfunction = hookfunction
local selfHookmetamethod = hookmetamethod

-- Debug Library
local selfDebugGetinfo = debug and debug.getinfo
local selfDebugGetmetatable = debug and debug.getmetatable
local selfDebugSetmetatable = debug and debug.setmetatable
local selfDebugGetupvalue = debug and debug.getupvalue

-- Unlock Protected Tables
-- Allow modification of core Lua tables for hooking
if selfSetreadonly then
	selfSetreadonly(debug, false)
	selfSetreadonly(task, false)
	selfSetreadonly(coroutine, false)
	selfSetreadonly(string, false)
	selfSetreadonly(table, false)
	selfSetreadonly(math, false)
end

-- Protection System Storage
-- Track hooked functions and their original references
local HOOKED_FUNCTIONS = {}
local FUNCTION_ADDRESS_MAP = {}
local CONTEXT_OVERRIDE = {}
local COROUTINE_CONTEXT = {}
local STABLE_REFERENCES = {}

-- Hook Chain Management
-- Maintain separate hook chains for game and executor contexts
local HOOK_CHAIN_REGISTRY = {}
local GAME_LAYER_CACHE = {}
local EXECUTOR_LAYER_CACHE = {}
local SCRIPT_LOCAL_HOOKS = {}

-- Recursion Protection
-- Prevent infinite loops in hook resolution
local HOOK_CALL_DEPTH = {}
local MAX_HOOK_DEPTH = 50
local CURRENTLY_RESOLVING = {}
local METAMETHOD_CALL_DEPTH = {}

-- LogService Isolation
-- Intercept and filter console messages by context
local PENDING_GAME_MESSAGES = {}
local MESSAGE_EMIT_GUARD = false

-- Call Stack Control
-- Bypass context detection when needed for internal operations
local CALLSTACK_BYPASS_ACTIVE = false
local ORIGINAL_METAMETHODS = {}

-- Context Detection
-- Determine if code is running from executor or game script
local function isExecutorScript()
	if CALLSTACK_BYPASS_ACTIVE then
		return false
	end
	
	local thread = selfCoroutineRunning()
	local threadId = selfTostring(thread)
	
	-- Check for manual context override
	if CONTEXT_OVERRIDE[threadId] then
		return CONTEXT_OVERRIDE[threadId].spoofedCaller
	end
	
	-- Check cached coroutine context
	if COROUTINE_CONTEXT[threadId] then
		return COROUTINE_CONTEXT[threadId] == "executor"
	end
	
	-- Use checkcaller if available and cache result
	if selfCheckcaller then
		local result = selfCheckcaller()
		COROUTINE_CONTEXT[threadId] = result and "executor" or "game"
		return result
	end
	
	return false
end

-- Script Identity Tracking
-- Get unique identifier for current script context
local function getScriptIdentity()
	local thread = selfCoroutineRunning()
	local threadId = selfTostring(thread)
	
	-- Try to get source file information
	if selfDebugGetinfo then
		local info = selfDebugGetinfo(2, "S")
		if info and info.source then
			return info.source
		end
	end
	
	return threadId
end

-- Stable Reference Management
-- Ensure consistent references across hook operations
local function getStableReference(originalRef)
	if not STABLE_REFERENCES[originalRef] then
		STABLE_REFERENCES[originalRef] = originalRef
	end
	return STABLE_REFERENCES[originalRef]
end

-- Hook Chain Initialization
-- Create hook chain structure for a function
local function initializeHookChain(funcRef)
	if not HOOK_CHAIN_REGISTRY[funcRef] then
		HOOK_CHAIN_REGISTRY[funcRef] = {
			original = funcRef,
			gameHooks = {},
			executorHooks = {},
			totalSize = 0
		}
	end
	return HOOK_CHAIN_REGISTRY[funcRef]
end

-- Add Game Context Hook
-- Register a hook that only affects game script calls
local function addGameHook(funcRef, hookFunc)
	local chain = initializeHookChain(funcRef)
	
	if chain.totalSize >= 100 then
		return false
	end
	
	selfTableInsert(chain.gameHooks, hookFunc)
	chain.totalSize = chain.totalSize + 1
	
	-- Invalidate cache when hooks change
	GAME_LAYER_CACHE[funcRef] = nil
	
	return true
end

-- Add Executor Context Hook
-- Register a hook that affects executor script calls
local function addExecutorHook(funcRef, hookFunc)
	local chain = initializeHookChain(funcRef)
	
	if chain.totalSize >= 100 then
		return false
	end
	
	selfTableInsert(chain.executorHooks, hookFunc)
	chain.totalSize = chain.totalSize + 1
	
	return true
end

-- Get Game Layer Function
-- Returns the appropriate function for game script context
local function getGameLayerFunction(funcRef)
	local chain = HOOK_CHAIN_REGISTRY[funcRef]
	if not chain then
		return funcRef
	end
	
	-- Return most recent game hook or original
	if #chain.gameHooks == 0 then
		return chain.original
	end
	
	return chain.gameHooks[#chain.gameHooks]
end

-- Get Executor Layer Function
-- Returns the appropriate function for executor context
local function getExecutorLayerFunction(funcRef)
	local chain = HOOK_CHAIN_REGISTRY[funcRef]
	if not chain then
		return funcRef
	end
	
	-- Executor hooks take precedence over game hooks
	if #chain.executorHooks > 0 then
		return chain.executorHooks[#chain.executorHooks]
	end
	
	if #chain.gameHooks > 0 then
		return chain.gameHooks[#chain.gameHooks]
	end
	
	return chain.original
end

-- Create Game Layer Wrapper
-- Wraps a function to route through correct hook chain
local function createGameLayerWrapper(originalFunc, gameLayerFunc)
	-- No wrapper needed if functions are identical
	if selfRawequal(originalFunc, gameLayerFunc) then
		return getStableReference(originalFunc)
	end
	
	-- Return cached wrapper if available
	local cachedWrapper = GAME_LAYER_CACHE[originalFunc]
	if cachedWrapper then
		return cachedWrapper
	end
	
	-- Create new wrapper with recursion protection
	local wrapper = function(...)
		local thread = selfCoroutineRunning()
		local threadId = selfTostring(thread)
		
		local depth = HOOK_CALL_DEPTH[threadId] or 0
		if depth >= MAX_HOOK_DEPTH then
			return gameLayerFunc(...)
		end
		
		HOOK_CALL_DEPTH[threadId] = depth + 1
		
		local executorLayerFunc = getExecutorLayerFunction(originalFunc)
		
		local results = {selfPcall(executorLayerFunc, ...)}
		
		HOOK_CALL_DEPTH[threadId] = depth
		
		if results[1] then
			return selfTableUnpack(results, 2)
		else
			selfError(results[2], 2)
		end
	end
	
	-- Convert to C closure if possible for better performance
	if selfNewcclosure then
		wrapper = selfNewcclosure(wrapper)
	end
	
	GAME_LAYER_CACHE[originalFunc] = wrapper
	return wrapper
end

-- Reference Resolution
-- Resolve function reference based on caller context
local function resolveReference(funcRef, callerContext)
	local resolutionKey = selfTostring(funcRef) .. "_" .. callerContext
	
	-- Prevent circular resolution
	if CURRENTLY_RESOLVING[resolutionKey] then
		return funcRef
	end
	
	CURRENTLY_RESOLVING[resolutionKey] = true
	
	local resolved = funcRef
	local success = selfPcall(function()
		if callerContext == "self" then
			resolved = funcRef
		elseif callerContext == "executor" then
			if EXECUTOR_LAYER_CACHE[funcRef] then
				resolved = EXECUTOR_LAYER_CACHE[funcRef]
			else
				resolved = getExecutorLayerFunction(funcRef)
				EXECUTOR_LAYER_CACHE[funcRef] = resolved
			end
		elseif callerContext == "game" then
			local scriptId = getScriptIdentity()
			
			-- Check for script-specific hooks first
			if SCRIPT_LOCAL_HOOKS[scriptId] and SCRIPT_LOCAL_HOOKS[scriptId][funcRef] then
				resolved = SCRIPT_LOCAL_HOOKS[scriptId][funcRef]
			else
				local gameLayerFunc = getGameLayerFunction(funcRef)
				resolved = createGameLayerWrapper(funcRef, gameLayerFunc)
			end
		end
	end)
	
	CURRENTLY_RESOLVING[resolutionKey] = nil
	
	if not success then
		return funcRef
	end
	
	return resolved
end

-- Cache Management
-- Clean up caches periodically to prevent memory bloat
local CACHE_SIZE_LIMIT = 1000
local CACHE_CLEANUP_THRESHOLD = 750
local STABLE_FUNCTION_REFERENCES = {}

local function cleanupCaches()
	-- Clean game layer cache
	local gameCacheSize = 0
	for _ in selfPairs(GAME_LAYER_CACHE) do
		gameCacheSize = gameCacheSize + 1
	end
	
	if gameCacheSize > CACHE_SIZE_LIMIT then
		local toRemove = gameCacheSize - CACHE_CLEANUP_THRESHOLD
		local removed = 0
		
		for key in selfPairs(GAME_LAYER_CACHE) do
			if removed >= toRemove then break end
			GAME_LAYER_CACHE[key] = nil
			removed = removed + 1
		end
	end
	
	-- Clean executor layer cache
	local executorCacheSize = 0
	for _ in selfPairs(EXECUTOR_LAYER_CACHE) do
		executorCacheSize = executorCacheSize + 1
	end
	
	if executorCacheSize > CACHE_SIZE_LIMIT then
		local toRemove = executorCacheSize - CACHE_CLEANUP_THRESHOLD
		local removed = 0
		
		for key in selfPairs(EXECUTOR_LAYER_CACHE) do
			if removed >= toRemove then break end
			EXECUTOR_LAYER_CACHE[key] = nil
			removed = removed + 1
		end
	end
	
	-- Clean dead coroutine contexts
	local deadThreads = {}
	
	for threadId, context in selfPairs(COROUTINE_CONTEXT) do
		-- Mark threads for cleanup
		-- Active threads will recreate entries naturally
		selfTableInsert(deadThreads, threadId)
	end
	
	for _, threadId in selfIpairs(deadThreads) do
		COROUTINE_CONTEXT[threadId] = nil
		CONTEXT_OVERRIDE[threadId] = nil
		HOOK_CALL_DEPTH[threadId] = nil
	end
	
	-- Clean pending message queue
	local pendingCount = 0
	for _ in selfPairs(PENDING_GAME_MESSAGES) do
		pendingCount = pendingCount + 1
	end
	
	if pendingCount > 100 then
		local toRemove = pendingCount - 50
		local removed = 0
		
		for key in selfPairs(PENDING_GAME_MESSAGES) do
			if removed >= toRemove then break end
			PENDING_GAME_MESSAGES[key] = nil
			removed = removed + 1
		end
	end
	
	-- Reset stable references if excessive
	local stableRefCount = 0
	for _ in selfPairs(STABLE_FUNCTION_REFERENCES) do
		stableRefCount = stableRefCount + 1
	end
	
	if stableRefCount > 500 then
		STABLE_FUNCTION_REFERENCES = {}
	end
end

-- LogService Message Tracking
local MESSAGE_HISTORY = {}
local MESSAGE_ID_COUNTER = 0

local LOG_MESSAGE_TYPE = {
	PRINT = "Print",
	WARN = "Warning",
	ERROR = "Error",
	INFO = "Info"
}

-- Capture Message
-- Store message in history with metadata
local function captureMessage(messageType, messageContent, context)
	MESSAGE_ID_COUNTER = MESSAGE_ID_COUNTER + 1
	
	local messageEntry = {
		id = MESSAGE_ID_COUNTER,
		type = messageType,
		message = messageContent,
		context = context,
		timestamp = selfOsTime()
	}
	
	selfTableInsert(MESSAGE_HISTORY, messageEntry)
	
	-- Keep history size reasonable
	if #MESSAGE_HISTORY > 500 then
		selfTableRemove(MESSAGE_HISTORY, 1)
	end
	
	return messageEntry
end

-- Format Message Arguments
-- Convert multiple arguments to single string
local function formatMessageArgs(...)
	local args = {...}
	local parts = {}
	
	for i = 1, selfSelect("#", ...) do
		local arg = args[i]
		if selfType(arg) == "string" then
			selfTableInsert(parts, arg)
		else
			selfTableInsert(parts, selfTostring(arg))
		end
	end
	
	return selfTableConcat(parts, " ")
end

-- Get Filtered Message History
-- Return messages visible to specific context
local function getFilteredMessageHistory(callerContext)
	local filtered = {}
	
	for _, entry in selfIpairs(MESSAGE_HISTORY) do
		local shouldInclude = false
		
		if callerContext == "self" then
			shouldInclude = true
		elseif callerContext == "executor" then
			if entry.context == "executor" or entry.context == "game" then
				shouldInclude = true
			end
		elseif callerContext == "game" then
			if entry.context == "game" then
				shouldInclude = true
			end
		end
		
		if shouldInclude then
			selfTableInsert(filtered, {
				message = entry.message,
				messageType = entry.type,
				timestamp = entry.timestamp
			})
		end
	end
	
	return filtered
end

-- Hook Print Function
-- Intercept print calls for message filtering
if selfNewcclosure then
	local originalPrint = selfPrint
	print = selfNewcclosure(function(...)
		local messageContent = formatMessageArgs(...)
		local context = isExecutorScript() and "executor" or "game"
		
		-- Check if call is from protection code
		local inProtectionCode = false
		if selfDebugGetinfo then
			local info = selfDebugGetinfo(2, "f")
			if info and info.func then
				if HOOKED_FUNCTIONS[info.func] then
					inProtectionCode = true
					context = "self"
				end
			end
		end
		
		captureMessage(LOG_MESSAGE_TYPE.PRINT, messageContent, context)
		
		if context == "game" then
			local messageKey = selfTostring(selfOsTime()) .. "_" .. messageContent
			PENDING_GAME_MESSAGES[messageKey] = {
				content = messageContent,
				type = LOG_MESSAGE_TYPE.PRINT,
				timestamp = selfTick()
			}
			originalPrint(...)
		elseif context == "executor" then
			originalPrint(...)
		end
	end)
	
	HOOKED_FUNCTIONS[print] = {
		name = "print",
		original = originalPrint
	}
end

-- Hook Warn Function
-- Intercept warn calls for message filtering
if selfNewcclosure then
	local originalWarn = selfWarn
	warn = selfNewcclosure(function(...)
		local messageContent = formatMessageArgs(...)
		local context = isExecutorScript() and "executor" or "game"
		
		local inProtectionCode = false
		if selfDebugGetinfo then
			local info = selfDebugGetinfo(2, "f")
			if info and info.func then
				if HOOKED_FUNCTIONS[info.func] then
					inProtectionCode = true
					context = "self"
				end
			end
		end
		
		captureMessage(LOG_MESSAGE_TYPE.WARN, messageContent, context)
		
		if context == "game" then
			local messageKey = selfTostring(selfOsTime()) .. "_" .. messageContent
			PENDING_GAME_MESSAGES[messageKey] = {
				content = messageContent,
				type = LOG_MESSAGE_TYPE.WARN,
				timestamp = selfTick()
			}
			originalWarn(...)
		elseif context == "executor" then
			originalWarn(...)
		end
	end)
	
	HOOKED_FUNCTIONS[warn] = {
		name = "warn",
		original = originalWarn
	}
end

-- Hook Error Function
-- Intercept error calls for tracking
if selfNewcclosure then
	local originalError = selfError
	error = selfNewcclosure(function(...)
		local messageContent = formatMessageArgs(...)
		local context = isExecutorScript() and "executor" or "game"
		
		local inProtectionCode = false
		if selfDebugGetinfo then
			local info = selfDebugGetinfo(2, "f")
			if info and info.func then
				if HOOKED_FUNCTIONS[info.func] then
					inProtectionCode = true
					context = "self"
				end
			end
		end
		
		captureMessage(LOG_MESSAGE_TYPE.ERROR, messageContent, context)
		
		originalError(...)
	end)
	
	HOOKED_FUNCTIONS[error] = {
		name = "error",
		original = originalError
	}
end

-- LogService Protection
-- Hook LogService to filter messages by context
local function InitializeLogServiceProtection()
	local success, LogService = selfPcall(function()
		return selfGame:GetService("LogService")
	end)
	
	if not success or not LogService then
		return
	end
	
	if not selfGetrawmetatable then
		return
	end
	
	local REAL_LOGSERVICE_MT = selfGetrawmetatable(LogService)
	if not REAL_LOGSERVICE_MT then
		return
	end
	
	if selfSetreadonly then
		selfSetreadonly(REAL_LOGSERVICE_MT, false)
	end
	
	local ORIGINAL_LOGSERVICE_INDEX = REAL_LOGSERVICE_MT.__index
	local ORIGINAL_LOGSERVICE_NAMECALL = REAL_LOGSERVICE_MT.__namecall
	
	ORIGINAL_METAMETHODS.LogService_index = ORIGINAL_LOGSERVICE_INDEX
	ORIGINAL_METAMETHODS.LogService_namecall = ORIGINAL_LOGSERVICE_NAMECALL
	
	if selfNewcclosure then
		REAL_LOGSERVICE_MT.__index = selfNewcclosure(function(self, key)
			if CALLSTACK_BYPASS_ACTIVE then
				return ORIGINAL_LOGSERVICE_INDEX(self, key)
			end
			
			local isExec = isExecutorScript()
			
			-- Hook GetLogHistory to return filtered messages
			if key == "GetLogHistory" then
				return function()
					local context = isExec and "executor" or "game"
					return getFilteredMessageHistory(context)
				end
			end
			
			-- Hook MessageOut signal to filter emitted messages
			if key == "MessageOut" then
				local originalSignal = ORIGINAL_LOGSERVICE_INDEX(self, key)
				
				if isExec then
					return originalSignal
				else
					-- Create proxy signal for game context
					local proxySignal = {}
					
					proxySignal.Connect = function(_, callback)
						local wrappedCallback = function(message, messageType)
							if MESSAGE_EMIT_GUARD then
								return
							end
							
							local messageKey = selfTostring(selfOsTime()) .. "_" .. message
							local pendingMessage = PENDING_GAME_MESSAGES[messageKey]
							
							-- Check if message is in pending queue
							if pendingMessage then
								local timeDiff = selfTick() - pendingMessage.timestamp
								
								if timeDiff < 0.05 and pendingMessage.content == message then
									PENDING_GAME_MESSAGES[messageKey] = nil
									callback(message, messageType)
									return
								end
							end
							
							-- Check if message is from game context
							local isGameMessage = false
							for _, entry in selfIpairs(MESSAGE_HISTORY) do
								if entry.context == "game" and entry.message == message then
									local timeSinceMessage = selfOsTime() - entry.timestamp
									if timeSinceMessage < 1 then
										isGameMessage = true
										break
									end
								end
							end
							
							if isGameMessage then
								callback(message, messageType)
							end
						end
						
						return originalSignal:Connect(wrappedCallback)
					end
					
					proxySignal.connect = proxySignal.Connect
					
					proxySignal.Wait = function(_)
						while true do
							local message, messageType = originalSignal:Wait()
							
							if not MESSAGE_EMIT_GUARD then
								local messageKey = selfTostring(selfOsTime()) .. "_" .. message
								local pendingMessage = PENDING_GAME_MESSAGES[messageKey]
								
								if pendingMessage then
									local timeDiff = selfTick() - pendingMessage.timestamp
									
									if timeDiff < 0.05 and pendingMessage.content == message then
										PENDING_GAME_MESSAGES[messageKey] = nil
										return message, messageType
									end
								end
								
								local isGameMessage = false
								for _, entry in selfIpairs(MESSAGE_HISTORY) do
									if entry.context == "game" and entry.message == message then
										local timeSinceMessage = selfOsTime() - entry.timestamp
										if timeSinceMessage < 1 then
											isGameMessage = true
											break
										end
									end
								end
								
								if isGameMessage then
									return message, messageType
								end
							end
						end
					end
					
					proxySignal.wait = proxySignal.Wait
					
					return proxySignal
				end
			end
			
			return ORIGINAL_LOGSERVICE_INDEX(self, key)
		end)
		
		REAL_LOGSERVICE_MT.__namecall = selfNewcclosure(function(self, ...)
			if CALLSTACK_BYPASS_ACTIVE then
				return ORIGINAL_LOGSERVICE_NAMECALL(self, ...)
			end
			
			local method = selfGetnamecallmethod and selfGetnamecallmethod() or ""
			local isExec = isExecutorScript()
			
			if method == "GetLogHistory" then
				local context = isExec and "executor" or "game"
				return getFilteredMessageHistory(context)
			end
			
			return ORIGINAL_LOGSERVICE_NAMECALL(self, ...)
		end)
	end
	
	if selfSetreadonly then
		selfSetreadonly(REAL_LOGSERVICE_MT, true)
	end
end

InitializeLogServiceProtection()

-- Closure Registry
-- Track closure types by context
local SELF_CLOSURE_TABLE = {}
local EXECUTOR_CLOSURE_TABLE = {}
local GAME_CLOSURE_TABLE = {}

local function registerSelfClosure(name, func)
	if not func then return end
	SELF_CLOSURE_TABLE[name] = {
		reference = func,
		isLua = selfIslclosure and selfIslclosure(func) or false,
		isC = selfIscclosure and selfIscclosure(func) or true
	}
end

local function registerExecutorClosure(name, func)
	if not func then return end
	EXECUTOR_CLOSURE_TABLE[func] = {
		name = name,
		isLua = selfIslclosure and selfIslclosure(func) or false,
		isC = selfIscclosure and selfIscclosure(func) or true
	}
end

local function registerGameClosure(name, func)
	if not func then return end
	GAME_CLOSURE_TABLE[func] = {
		name = name,
		isLua = selfIslclosure and selfIslclosure(func) or false,
		isC = selfIscclosure and selfIscclosure(func) or true
	}
end

-- Hook Shadow Table
-- Track hook installations and metadata
local HOOK_SHADOW_TABLE = {}

local function registerHookShadow(functionName, originalFunc, executorHook)
	if not HOOK_SHADOW_TABLE[functionName] then
		HOOK_SHADOW_TABLE[functionName] = {
			original = originalFunc,
			executorHook = executorHook,
			installedTime = selfOsTime(),
			callCount = 0
		}
	else
		HOOK_SHADOW_TABLE[functionName].executorHook = executorHook
	end
end

-- Function Address Mapping
-- Store function addresses for spoofing
if selfDebugGetinfo then
	FUNCTION_ADDRESS_MAP[selfDebugGetinfo] = selfTostring(selfDebugGetinfo)
end
if selfDebugGetupvalue then
	FUNCTION_ADDRESS_MAP[selfDebugGetupvalue] = selfTostring(selfDebugGetupvalue)
end
FUNCTION_ADDRESS_MAP[selfTostring] = selfTostring(selfTostring)
FUNCTION_ADDRESS_MAP[selfRawequal] = selfTostring(selfRawequal)
FUNCTION_ADDRESS_MAP[selfPrint] = selfTostring(selfPrint)
FUNCTION_ADDRESS_MAP[selfWarn] = selfTostring(selfWarn)
if selfCheckcaller then
	FUNCTION_ADDRESS_MAP[selfCheckcaller] = selfTostring(selfCheckcaller)
end
if selfGetgc then
	FUNCTION_ADDRESS_MAP[selfGetgc] = selfTostring(selfGetgc)
end

-- Hook Debug.getinfo
-- Spoof debug info for hooked functions
if selfDebugGetinfo and selfNewcclosure then
	debug.getinfo = selfNewcclosure(function(f, what)
		if HOOKED_FUNCTIONS[f] then
			local original = HOOKED_FUNCTIONS[f].original
			return selfDebugGetinfo(original, what)
		end
		return selfDebugGetinfo(f, what)
	end)
	
	HOOKED_FUNCTIONS[debug.getinfo] = {
		name = "debug.getinfo",
		original = selfDebugGetinfo
	}
end

-- Hook Debug.getupvalue
-- Spoof upvalues for hooked functions
if selfDebugGetupvalue and selfNewcclosure then
	debug.getupvalue = selfNewcclosure(function(f, index)
		if HOOKED_FUNCTIONS[f] then
			local original = HOOKED_FUNCTIONS[f].original
			return selfDebugGetupvalue(original, index)
		end
		return selfDebugGetupvalue(f, index)
	end)
	
	HOOKED_FUNCTIONS[debug.getupvalue] = {
		name = "debug.getupvalue",
		original = selfDebugGetupvalue
	}
end

-- Hook Tostring
-- Spoof addresses for hooked functions
if selfNewcclosure then
	tostring = selfNewcclosure(function(v)
		if HOOKED_FUNCTIONS[v] then
			local original = HOOKED_FUNCTIONS[v].original
			return FUNCTION_ADDRESS_MAP[original] or selfTostring(original)
		end
		return selfTostring(v)
	end)
	
	HOOKED_FUNCTIONS[tostring] = {
		name = "tostring",
		original = selfTostring
	}
end

-- Hook Rawequal
-- Make hooked functions compare equal to originals
local selfRawequalOriginal = selfRawequal
if selfNewcclosure then
	rawequal = selfNewcclosure(function(v1, v2)
		if HOOKED_FUNCTIONS[v1] and selfRawequalOriginal(v2, HOOKED_FUNCTIONS[v1].original) then
			return true
		end
		if HOOKED_FUNCTIONS[v2] and selfRawequalOriginal(v1, HOOKED_FUNCTIONS[v2].original) then
			return true
		end
		return selfRawequalOriginal(v1, v2)
	end)
	
	HOOKED_FUNCTIONS[rawequal] = {
		name = "rawequal",
		original = selfRawequalOriginal
	}
end

-- Hook Islclosure
-- Context-aware Lua closure detection
if selfIslclosure and selfNewcclosure then
	islclosure = selfNewcclosure(function(f)
		local isExec = isExecutorScript()
		local closureTable = isExec and EXECUTOR_CLOSURE_TABLE or GAME_CLOSURE_TABLE
		
		local entry = closureTable[f]
		if entry then
			return entry.isLua
		end
		
		return selfIslclosure(f)
	end)
	
	HOOKED_FUNCTIONS[islclosure] = {
		name = "islclosure",
		original = selfIslclosure
	}
end

-- Hook Iscclosure
-- Context-aware C closure detection
if selfIscclosure and selfNewcclosure then
	iscclosure = selfNewcclosure(function(f)
		local isExec = isExecutorScript()
		local closureTable = isExec and EXECUTOR_CLOSURE_TABLE or GAME_CLOSURE_TABLE
		
		local entry = closureTable[f]
		if entry then
			return entry.isC
		end
		
		return selfIscclosure(f)
	end)
	
	HOOKED_FUNCTIONS[iscclosure] = {
		name = "iscclosure",
		original = selfIscclosure
	}
end

-- Hook Getgc
-- Filter garbage collector results to hide protection tables
if selfGetgc and selfNewcclosure then
	getgc = selfNewcclosure(function(include_tables)
		local results = selfGetgc(include_tables)
		local filtered = {}
		
		for _, obj in selfIpairs(results) do
			local should_hide = false
			
			-- Hide hooked functions
			if HOOKED_FUNCTIONS[obj] then
				should_hide = true
			end
			
			-- Hide protection tables
			if selfType(obj) == "table" then
				if selfRawget(obj, "HOOKED_FUNCTIONS") or 
				   selfRawget(obj, "PROTECTED_SERVICES") or
				   selfRawget(obj, "PROTECTED_INSTANCES") or
				   selfRawget(obj, "EXECUTOR_CLOSURE_TABLE") or
				   selfRawget(obj, "GAME_CLOSURE_TABLE") or
				   selfRawget(obj, "SELF_CLOSURE_TABLE") or
				   selfRawget(obj, "HOOK_SHADOW_TABLE") or
				   selfRawget(obj, "COROUTINE_CONTEXT") or
				   selfRawget(obj, "MESSAGE_HISTORY") or
				   selfRawget(obj, "HOOK_CHAIN_REGISTRY") or
				   selfRawget(obj, "GAME_LAYER_CACHE") or
				   selfRawget(obj, "EXECUTOR_LAYER_CACHE") or
				   selfRawget(obj, "SCRIPT_LOCAL_HOOKS") or
				   selfRawget(obj, "PENDING_GAME_MESSAGES") or
				   selfRawget(obj, "STABLE_REFERENCES") or
				   selfRawget(obj, "ORIGINAL_METAMETHODS") then
					should_hide = true
				end
			end
			
			if not should_hide then
				selfTableInsert(filtered, obj)
			end
		end
		
		return filtered
	end)
	
	HOOKED_FUNCTIONS[getgc] = {
		name = "getgc",
		original = selfGetgc
	}
end

-- Hook Hookfunction
-- Intercept hook installations to maintain proper layering
if selfHookfunction and selfNewcclosure then
	hookfunction = selfNewcclosure(function(target, replacement)
		local targetName = selfTostring(target)
		
		registerHookShadow(targetName, target, replacement)
		
		local isExec = isExecutorScript()
		if isExec then
			addExecutorHook(target, replacement)
			registerExecutorClosure(targetName, replacement)
			registerGameClosure(targetName .. "_exec_hook", replacement)
		else
			addGameHook(target, replacement)
			registerGameClosure(targetName, replacement)
		end
		
		return selfHookfunction(target, replacement)
	end)
	
	HOOKED_FUNCTIONS[hookfunction] = {
		name = "hookfunction",
		original = selfHookfunction
	}
end

-- Hook Hookmetamethod
-- Intercept metamethod hook installations
if selfHookmetamethod and selfNewcclosure then
	hookmetamethod = selfNewcclosure(function(obj, method, replacement)
		local methodName = selfTostring(method)
		local objName = selfTostring(obj)
		
		local hookName = objName .. "." .. methodName
		registerHookShadow(hookName, nil, replacement)
		
		local isExec = isExecutorScript()
		if isExec then
			registerExecutorClosure(hookName, replacement)
			registerGameClosure(hookName .. "_exec_hook", replacement)
		else
			registerGameClosure(hookName, replacement)
		end
		
		return selfHookmetamethod(obj, method, replacement)
	end)
	
	HOOKED_FUNCTIONS[hookmetamethod] = {
		name = "hookmetamethod",
		original = selfHookmetamethod
	}
end

-- Hook Checkcaller
-- Redirect to context detection function
if selfCheckcaller and selfNewcclosure then
	checkcaller = selfNewcclosure(isExecutorScript)
	
	HOOKED_FUNCTIONS[checkcaller] = {
		name = "checkcaller",
		original = selfCheckcaller
	}
end

-- Coroutine Context Tracking
-- Inherit context when creating new coroutines
if selfNewcclosure then
	local originalCoroutineCreate = selfCoroutineCreate
	coroutine.create = selfNewcclosure(function(f)
		local parentContext = isExecutorScript() and "executor" or "game"
		local co = originalCoroutineCreate(f)
		local coId = selfTostring(co)
		COROUTINE_CONTEXT[coId] = parentContext
		return co
	end)
	
	local originalCoroutineWrap = selfCoroutineWrap
	coroutine.wrap = selfNewcclosure(function(f)
		local parentContext = isExecutorScript() and "executor" or "game"
		local co = originalCoroutineCreate(f)
		local coId = selfTostring(co)
		COROUTINE_CONTEXT[coId] = parentContext
		return originalCoroutineWrap(f)
	end)
	
	local originalCoroutineResume = selfCoroutineResume
	coroutine.resume = selfNewcclosure(function(co, ...)
		local coId = selfTostring(co)
		if not COROUTINE_CONTEXT[coId] then
			local parentContext = isExecutorScript() and "executor" or "game"
			COROUTINE_CONTEXT[coId] = parentContext
		end
		return originalCoroutineResume(co, ...)
	end)
end

-- Module Loading Context Tracking
-- Track which context loaded each module
local MODULE_CONTEXT = {}
local MODULE_RETURN_CACHE = {}

if selfNewcclosure then
	local currentRequire = require
	
	require = function(module, ...)
		local loaderContext = isExecutorScript() and "executor" or "game"
		
		local moduleInstance
		if selfType(module) == "string" then
			moduleInstance = module
		else
			moduleInstance = selfTostring(module)
		end
		
		if not MODULE_CONTEXT[moduleInstance] then
			MODULE_CONTEXT[moduleInstance] = loaderContext
		end
		
		local result = currentRequire(module, ...)
		
		if selfType(result) == "function" then
			MODULE_RETURN_CACHE[result] = {
				module = moduleInstance,
				context = loaderContext,
				timestamp = selfTick()
			}
		end
		
		return result
	end
	
	HOOKED_FUNCTIONS[require] = {
		name = "require",
		original = selfRequire
	}
end

-- Metatable Protection System
-- Provides three-layer isolation for metatables
local function InitializeMetatableProtection()
	if not selfGetrawmetatable then
		return
	end
	
	local REAL_GAME_MT = selfGetrawmetatable(selfGame)
	if not REAL_GAME_MT then
		return
	end
	
	if selfSetreadonly then
		selfSetreadonly(REAL_GAME_MT, false)
	end
	
	local ORIGINAL_NAMECALL = REAL_GAME_MT.__namecall
	local ORIGINAL_INDEX = REAL_GAME_MT.__index
	local ORIGINAL_NEWINDEX = REAL_GAME_MT.__newindex
	
	ORIGINAL_METAMETHODS.game_namecall = ORIGINAL_NAMECALL
	ORIGINAL_METAMETHODS.game_index = ORIGINAL_INDEX
	ORIGINAL_METAMETHODS.game_newindex = ORIGINAL_NEWINDEX
	
	registerSelfClosure("game.__namecall", ORIGINAL_NAMECALL)
	registerSelfClosure("game.__index", ORIGINAL_INDEX)
	if ORIGINAL_NEWINDEX then
		registerSelfClosure("game.__newindex", ORIGINAL_NEWINDEX)
	end
	
	local EXECUTOR_GAME_MT = {}
	local GAME_GAME_MT = {}
	
	local PROTECTED_SERVICES = {}
	local PROTECTED_INSTANCES = {}
	
	-- Create Executor Metatable
	-- Copy metatable with all metamethods for executor context
	local function createExecutorMetatable(realMt)
		local execMt = {}
		execMt.__metatable = "The metatable is locked"
		
		for k, v in selfPairs(realMt) do
			if k ~= "__namecall" and k ~= "__index" and k ~= "__newindex" then
				if selfType(v) == "function" then
					if selfNewcclosure then
						execMt[k] = selfNewcclosure(v)
					else
						execMt[k] = v
					end
				else
					execMt[k] = v
				end
			end
		end
		
		execMt.__namecall = ORIGINAL_NAMECALL
		execMt.__index = ORIGINAL_INDEX
		if ORIGINAL_NEWINDEX then
			execMt.__newindex = ORIGINAL_NEWINDEX
		end
		
		return execMt
	end
	
	-- Create Game Metatable
	-- Copy metatable for game script context
	local function createGameMetatable(realMt)
		local gameMt = {}
		gameMt.__metatable = "The metatable is locked"
		
		for k, v in selfPairs(realMt) do
			if k ~= "__namecall" and k ~= "__index" and k ~= "__newindex" then
				if selfType(v) == "function" then
					if selfNewcclosure then
						gameMt[k] = selfNewcclosure(v)
					else
						gameMt[k] = v
					end
				else
					gameMt[k] = v
				end
			end
		end
		
		gameMt.__namecall = ORIGINAL_NAMECALL
		gameMt.__index = ORIGINAL_INDEX
		if ORIGINAL_NEWINDEX then
			gameMt.__newindex = ORIGINAL_NEWINDEX
		end
		
		return gameMt
	end
	
	EXECUTOR_GAME_MT = createExecutorMetatable(REAL_GAME_MT)
	GAME_GAME_MT = createGameMetatable(REAL_GAME_MT)
	
	registerExecutorClosure("game.__namecall", EXECUTOR_GAME_MT.__namecall)
	registerExecutorClosure("game.__index", EXECUTOR_GAME_MT.__index)
	if EXECUTOR_GAME_MT.__newindex then
		registerExecutorClosure("game.__newindex", EXECUTOR_GAME_MT.__newindex)
	end
	
	registerGameClosure("game.__namecall", GAME_GAME_MT.__namecall)
	registerGameClosure("game.__index", GAME_GAME_MT.__index)
	if GAME_GAME_MT.__newindex then
		registerGameClosure("game.__newindex", GAME_GAME_MT.__newindex)
	end
	
	-- Protect Service
	-- Apply protection to a Roblox service
	local function protectService(service, serviceName)
		if PROTECTED_SERVICES[service] then
			return
		end
		
		local realMt = selfGetrawmetatable(service)
		if not realMt then
			return
		end
		
		if selfSetreadonly then
			selfSetreadonly(realMt, false)
		end
		
		local originalNamecall = realMt.__namecall
		local originalIndex = realMt.__index
		local originalNewindex = realMt.__newindex
		
		ORIGINAL_METAMETHODS[serviceName .. "_namecall"] = originalNamecall
		ORIGINAL_METAMETHODS[serviceName .. "_index"] = originalIndex
		ORIGINAL_METAMETHODS[serviceName .. "_newindex"] = originalNewindex
		
		local executorMt = createExecutorMetatable(realMt)
		local gameMt = createGameMetatable(realMt)
		
		if originalNamecall then
			registerExecutorClosure(serviceName .. ".__namecall", executorMt.__namecall)
			registerGameClosure(serviceName .. ".__namecall", gameMt.__namecall)
		end
		if originalIndex then
			registerExecutorClosure(serviceName .. ".__index", executorMt.__index)
			registerGameClosure(serviceName .. ".__index", gameMt.__index)
		end
		if originalNewindex then
			registerExecutorClosure(serviceName .. ".__newindex", executorMt.__newindex)
			registerGameClosure(serviceName .. ".__newindex", gameMt.__newindex)
		end
		
		-- Hook Namecall with Context Awareness
		if selfNewcclosure then
			realMt.__namecall = selfNewcclosure(function(self, ...)
				local thread = selfCoroutineRunning()
				local threadId = selfTostring(thread)
				local depth = METAMETHOD_CALL_DEPTH[threadId] or 0
				
				-- Prevent recursion
				if depth > 0 then
					CALLSTACK_BYPASS_ACTIVE = true
					local result = {originalNamecall(self, ...)}
					CALLSTACK_BYPASS_ACTIVE = false
					return selfTableUnpack(result)
				end
				
				METAMETHOD_CALL_DEPTH[threadId] = depth + 1
				
				local isExec = isExecutorScript()
				
				local results
				if isExec then
					local execFunc = executorMt.__namecall
					if execFunc and execFunc ~= originalNamecall then
						results = {execFunc(self, ...)}
					else
						results = {originalNamecall(self, ...)}
					end
				else
					CALLSTACK_BYPASS_ACTIVE = true
					local gameFunc = gameMt.__namecall
					if gameFunc and gameFunc ~= originalNamecall then
						results = {gameFunc(self, ...)}
					else
						results = {originalNamecall(self, ...)}
					end
					CALLSTACK_BYPASS_ACTIVE = false
				end
				
				METAMETHOD_CALL_DEPTH[threadId] = depth
				
				return selfTableUnpack(results)
			end)
			
			-- Hook Index with Function Resolution
			realMt.__index = selfNewcclosure(function(t, k)
				local thread = selfCoroutineRunning()
				local threadId = selfTostring(thread)
				local depth = METAMETHOD_CALL_DEPTH[threadId] or 0
				
				if depth > 0 then
					CALLSTACK_BYPASS_ACTIVE = true
					local result = originalIndex(t, k)
					CALLSTACK_BYPASS_ACTIVE = false
					return result
				end
				
				METAMETHOD_CALL_DEPTH[threadId] = depth + 1
				
				local isExec = isExecutorScript()
				
				if selfType(k) == "string" then
					local indexResult
					if isExec then
						local execFunc = executorMt.__index
						if execFunc and execFunc ~= originalIndex then
							indexResult = execFunc(t, k)
						else
							indexResult = originalIndex(t, k)
						end
					else
						CALLSTACK_BYPASS_ACTIVE = true
						local gameFunc = gameMt.__index
						if gameFunc and gameFunc ~= originalIndex then
							indexResult = gameFunc(t, k)
						else
							indexResult = originalIndex(t, k)
						end
						CALLSTACK_BYPASS_ACTIVE = false
					end
					
					METAMETHOD_CALL_DEPTH[threadId] = depth
					
					-- Resolve function references for proper hook routing
					if selfType(indexResult) == "function" then
						local callerContext = isExec and "executor" or "game"
						return resolveReference(indexResult, callerContext)
					end
					
					return indexResult
				end
				
				local result
				if isExec then
					local execFunc = executorMt.__index
					if execFunc and execFunc ~= originalIndex then
						result = execFunc(t, k)
					else
						result = originalIndex(t, k)
					end
				else
					CALLSTACK_BYPASS_ACTIVE = true
					local gameFunc = gameMt.__index
					if gameFunc and gameFunc ~= originalIndex then
						result = gameFunc(t, k)
					else
						result = originalIndex(t, k)
					end
					CALLSTACK_BYPASS_ACTIVE = false
				end
				
				METAMETHOD_CALL_DEPTH[threadId] = depth
				
				return result
			end)
			
			-- Hook Newindex with Script-Local Hook Tracking
			realMt.__newindex = selfNewcclosure(function(t, k, v)
				local thread = selfCoroutineRunning()
				local threadId = selfTostring(thread)
				local depth = METAMETHOD_CALL_DEPTH[threadId] or 0
				
				if depth > 0 then
					CALLSTACK_BYPASS_ACTIVE = true
					if originalNewindex then
						originalNewindex(t, k, v)
					end
					CALLSTACK_BYPASS_ACTIVE = false
					return
				end
				
				METAMETHOD_CALL_DEPTH[threadId] = depth + 1
				
				local isExec = isExecutorScript()
				
				if isExec then
					local execFunc = executorMt.__newindex
					if execFunc and execFunc ~= originalNewindex then
						execFunc(t, k, v)
					else
						if originalNewindex then
							originalNewindex(t, k, v)
						end
					end
				else
					-- Track script-local function hooks
					if selfType(v) == "function" then
						local scriptId = getScriptIdentity()
						if not SCRIPT_LOCAL_HOOKS[scriptId] then
							SCRIPT_LOCAL_HOOKS[scriptId] = {}
						end
						CALLSTACK_BYPASS_ACTIVE = true
						local oldValue = originalIndex(t, k)
						CALLSTACK_BYPASS_ACTIVE = false
						if oldValue then
							SCRIPT_LOCAL_HOOKS[scriptId][oldValue] = v
							GAME_LAYER_CACHE[oldValue] = nil
						end
					end
					
					CALLSTACK_BYPASS_ACTIVE = true
					local gameFunc = gameMt.__newindex
					if gameFunc and gameFunc ~= originalNewindex then
						gameFunc(t, k, v)
					else
						if originalNewindex then
							originalNewindex(t, k, v)
						end
					end
					CALLSTACK_BYPASS_ACTIVE = false
				end
				
				METAMETHOD_CALL_DEPTH[threadId] = depth
			end)
		end
		
		if selfSetreadonly then
			selfSetreadonly(realMt, true)
		end
		
		PROTECTED_SERVICES[service] = {
			realMt = realMt,
			executorMt = executorMt,
			gameMt = gameMt,
			originalNamecall = originalNamecall,
			originalIndex = originalIndex,
			originalNewindex = originalNewindex
		}
	end
	
	-- Protect Instance Type
	-- Apply protection to all instances of a specific type
	local function protectInstanceType(instance, instanceType)
		if PROTECTED_INSTANCES[instanceType] then
			return
		end
		
		local realMt = selfGetrawmetatable(instance)
		if not realMt then
			return
		end
		
		if selfSetreadonly then
			selfSetreadonly(realMt, false)
		end
		
		local originalNamecall = realMt.__namecall
		local originalIndex = realMt.__index
		local originalNewindex = realMt.__newindex
		
		ORIGINAL_METAMETHODS[instanceType .. "_namecall"] = originalNamecall
		ORIGINAL_METAMETHODS[instanceType .. "_index"] = originalIndex
		ORIGINAL_METAMETHODS[instanceType .. "_newindex"] = originalNewindex
		
		local executorMt = createExecutorMetatable(realMt)
		local gameMt = createGameMetatable(realMt)
		
		if selfNewcclosure then
			realMt.__namecall = selfNewcclosure(function(self, ...)
				local thread = selfCoroutineRunning()
				local threadId = selfTostring(thread)
				local depth = METAMETHOD_CALL_DEPTH[threadId] or 0
				
				if depth > 0 then
					CALLSTACK_BYPASS_ACTIVE = true
					local result = {originalNamecall(self, ...)}
					CALLSTACK_BYPASS_ACTIVE = false
					return selfTableUnpack(result)
				end
				
				METAMETHOD_CALL_DEPTH[threadId] = depth + 1
				
				local isExec = isExecutorScript()
				
				local results
				if isExec then
					local execFunc = executorMt.__namecall
					if execFunc and execFunc ~= originalNamecall then
						results = {execFunc(self, ...)}
					else
						results = {originalNamecall(self, ...)}
					end
				else
					CALLSTACK_BYPASS_ACTIVE = true
					local gameFunc = gameMt.__namecall
					if gameFunc and gameFunc ~= originalNamecall then
						results = {gameFunc(self, ...)}
					else
						results = {originalNamecall(self, ...)}
					end
					CALLSTACK_BYPASS_ACTIVE = false
				end
				
				METAMETHOD_CALL_DEPTH[threadId] = depth
				
				return selfTableUnpack(results)
			end)
			
			realMt.__index = selfNewcclosure(function(t, k)
				local thread = selfCoroutineRunning()
				local threadId = selfTostring(thread)
				local depth = METAMETHOD_CALL_DEPTH[threadId] or 0
				
				if depth > 0 then
					CALLSTACK_BYPASS_ACTIVE = true
					local result = originalIndex(t, k)
					CALLSTACK_BYPASS_ACTIVE = false
					return result
				end
				
				METAMETHOD_CALL_DEPTH[threadId] = depth + 1
				
				local isExec = isExecutorScript()
				
				if selfType(k) == "string" then
					local indexResult
					if isExec then
						local execFunc = executorMt.__index
						if execFunc and execFunc ~= originalIndex then
							indexResult = execFunc(t, k)
						else
							indexResult = originalIndex(t, k)
						end
					else
						CALLSTACK_BYPASS_ACTIVE = true
						local gameFunc = gameMt.__index
						if gameFunc and gameFunc ~= originalIndex then
							indexResult = gameFunc(t, k)
						else
							indexResult = originalIndex(t, k)
						end
						CALLSTACK_BYPASS_ACTIVE = false
					end
					
					METAMETHOD_CALL_DEPTH[threadId] = depth
					
					if selfType(indexResult) == "function" then
						local callerContext = isExec and "executor" or "game"
						return resolveReference(indexResult, callerContext)
					end
					
					return indexResult
				end
				
				local result
				if isExec then
					local execFunc = executorMt.__index
					if execFunc and execFunc ~= originalIndex then
						result = execFunc(t, k)
					else
						result = originalIndex(t, k)
					end
				else
					CALLSTACK_BYPASS_ACTIVE = true
					local gameFunc = gameMt.__index
					if gameFunc and gameFunc ~= originalIndex then
						result = gameFunc(t, k)
					else
						result = originalIndex(t, k)
					end
					CALLSTACK_BYPASS_ACTIVE = false
				end
				
				METAMETHOD_CALL_DEPTH[threadId] = depth
				
				return result
			end)
			
			realMt.__newindex = selfNewcclosure(function(t, k, v)
				local thread = selfCoroutineRunning()
				local threadId = selfTostring(thread)
				local depth = METAMETHOD_CALL_DEPTH[threadId] or 0
				
				if depth > 0 then
					CALLSTACK_BYPASS_ACTIVE = true
					if originalNewindex then
						originalNewindex(t, k, v)
					end
					CALLSTACK_BYPASS_ACTIVE = false
					return
				end
				
				METAMETHOD_CALL_DEPTH[threadId] = depth + 1
				
				local isExec = isExecutorScript()
				
				if isExec then
					local execFunc = executorMt.__newindex
					if execFunc and execFunc ~= originalNewindex then
						execFunc(t, k, v)
					else
						if originalNewindex then
							originalNewindex(t, k, v)
						end
					end
				else
					CALLSTACK_BYPASS_ACTIVE = true
					local gameFunc = gameMt.__newindex
					if gameFunc and gameFunc ~= originalNewindex then
						gameFunc(t, k, v)
					else
						if originalNewindex then
							originalNewindex(t, k, v)
						end
					end
					CALLSTACK_BYPASS_ACTIVE = false
				end
				
				METAMETHOD_CALL_DEPTH[threadId] = depth
			end)
		end
		
		if selfSetreadonly then
			selfSetreadonly(realMt, true)
		end
		
		PROTECTED_INSTANCES[instanceType] = {
			realMt = realMt,
			executorMt = executorMt,
			gameMt = gameMt,
			originalNamecall = originalNamecall,
			originalIndex = originalIndex,
			originalNewindex = originalNewindex
		}
	end
	
	-- Hook Game Metatable
	if selfNewcclosure then
		REAL_GAME_MT.__namecall = selfNewcclosure(function(self, ...)
			local thread = selfCoroutineRunning()
			local threadId = selfTostring(thread)
			local depth = METAMETHOD_CALL_DEPTH[threadId] or 0
			
			if depth > 0 then
				CALLSTACK_BYPASS_ACTIVE = true
				local result = {ORIGINAL_NAMECALL(self, ...)}
				CALLSTACK_BYPASS_ACTIVE = false
				return selfTableUnpack(result)
			end
			
			METAMETHOD_CALL_DEPTH[threadId] = depth + 1
			
			local isExec = isExecutorScript()
			
			local results
			if isExec then
				local execFunc = EXECUTOR_GAME_MT.__namecall
				if execFunc and execFunc ~= ORIGINAL_NAMECALL then
					results = {execFunc(self, ...)}
				else
					results = {ORIGINAL_NAMECALL(self, ...)}
				end
			else
				CALLSTACK_BYPASS_ACTIVE = true
				local gameFunc = GAME_GAME_MT.__namecall
				if gameFunc and gameFunc ~= ORIGINAL_NAMECALL then
					results = {gameFunc(self, ...)}
				else
					results = {ORIGINAL_NAMECALL(self, ...)}
				end
				CALLSTACK_BYPASS_ACTIVE = false
			end
			
			METAMETHOD_CALL_DEPTH[threadId] = depth
			
			return selfTableUnpack(results)
		end)
		
		REAL_GAME_MT.__index = selfNewcclosure(function(t, k)
			local thread = selfCoroutineRunning()
			local threadId = selfTostring(thread)
			local depth = METAMETHOD_CALL_DEPTH[threadId] or 0
			
			if depth > 0 then
				CALLSTACK_BYPASS_ACTIVE = true
				local result = ORIGINAL_INDEX(t, k)
				CALLSTACK_BYPASS_ACTIVE = false
				return result
			end
			
			METAMETHOD_CALL_DEPTH[threadId] = depth + 1
			
			local isExec = isExecutorScript()
			
			if selfType(k) == "string" then
				local indexResult
				if isExec then
					local execFunc = EXECUTOR_GAME_MT.__index
					if execFunc and execFunc ~= ORIGINAL_INDEX then
						indexResult = execFunc(t, k)
					else
						indexResult = ORIGINAL_INDEX(t, k)
					end
				else
					CALLSTACK_BYPASS_ACTIVE = true
					local gameFunc = GAME_GAME_MT.__index
					if gameFunc and gameFunc ~= ORIGINAL_INDEX then
						indexResult = gameFunc(t, k)
					else
						indexResult = ORIGINAL_INDEX(t, k)
					end
					CALLSTACK_BYPASS_ACTIVE = false
				end
				
				METAMETHOD_CALL_DEPTH[threadId] = depth
				
				if selfType(indexResult) == "function" then
					local callerContext = isExec and "executor" or "game"
					return resolveReference(indexResult, callerContext)
				end
				
				return indexResult
			end
			
			local result
			if isExec then
				local execFunc = EXECUTOR_GAME_MT.__index
				if execFunc and execFunc ~= ORIGINAL_INDEX then
					result = execFunc(t, k)
				else
					result = ORIGINAL_INDEX(t, k)
				end
			else
				CALLSTACK_BYPASS_ACTIVE = true
				local gameFunc = GAME_GAME_MT.__index
				if gameFunc and gameFunc ~= ORIGINAL_INDEX then
					result = gameFunc(t, k)
				else
					result = ORIGINAL_INDEX(t, k)
				end
				CALLSTACK_BYPASS_ACTIVE = false
			end
			
			METAMETHOD_CALL_DEPTH[threadId] = depth
			
			return result
		end)
		
		REAL_GAME_MT.__newindex = selfNewcclosure(function(t, k, v)
			local thread = selfCoroutineRunning()
			local threadId = selfTostring(thread)
			local depth = METAMETHOD_CALL_DEPTH[threadId] or 0
			
			if depth > 0 then
				CALLSTACK_BYPASS_ACTIVE = true
				if ORIGINAL_NEWINDEX then
					ORIGINAL_NEWINDEX(t, k, v)
				end
				CALLSTACK_BYPASS_ACTIVE = false
				return
			end
			
			METAMETHOD_CALL_DEPTH[threadId] = depth + 1
			
			local isExec = isExecutorScript()
			
			if isExec then
				local execFunc = EXECUTOR_GAME_MT.__newindex
				if execFunc and execFunc ~= ORIGINAL_NEWINDEX then
					execFunc(t, k, v)
				else
					if ORIGINAL_NEWINDEX then
						ORIGINAL_NEWINDEX(t, k, v)
					end
				end
			else
				CALLSTACK_BYPASS_ACTIVE = true
				local gameFunc = GAME_GAME_MT.__newindex
				if gameFunc and gameFunc ~= ORIGINAL_NEWINDEX then
					gameFunc(t, k, v)
				else
					if ORIGINAL_NEWINDEX then
						ORIGINAL_NEWINDEX(t, k, v)
					end
				end
				CALLSTACK_BYPASS_ACTIVE = false
			end
			
			METAMETHOD_CALL_DEPTH[threadId] = depth
		end)
	end
	
	-- Enhanced Rawequal
	-- Make metatable layers compare as equal
	if selfNewcclosure then
		rawequal = selfNewcclosure(function(v1, v2)
			if HOOKED_FUNCTIONS[v1] and selfRawequalOriginal(v2, HOOKED_FUNCTIONS[v1].original) then
				return true
			end
			if HOOKED_FUNCTIONS[v2] and selfRawequalOriginal(v1, HOOKED_FUNCTIONS[v2].original) then
				return true
			end
			
			if (v1 == EXECUTOR_GAME_MT and selfRawequalOriginal(v2, REAL_GAME_MT)) or
			   (v2 == EXECUTOR_GAME_MT and selfRawequalOriginal(v1, REAL_GAME_MT)) then
				return true
			end
			
			if (v1 == GAME_GAME_MT and selfRawequalOriginal(v2, REAL_GAME_MT)) or
			   (v2 == GAME_GAME_MT and selfRawequalOriginal(v1, REAL_GAME_MT)) then
				return true
			end
			
			if (v1 == EXECUTOR_GAME_MT and selfRawequalOriginal(v2, GAME_GAME_MT)) or
			   (v2 == EXECUTOR_GAME_MT and selfRawequalOriginal(v1, GAME_GAME_MT)) then
				return false
			end
			
			for service, data in selfPairs(PROTECTED_SERVICES) do
				if (v1 == data.executorMt and selfRawequalOriginal(v2, data.realMt)) or
				   (v2 == data.executorMt and selfRawequalOriginal(v1, data.realMt)) then
					return true
				end
				if (v1 == data.gameMt and selfRawequalOriginal(v2, data.realMt)) or
				   (v2 == data.gameMt and selfRawequalOriginal(v1, data.realMt)) then
					return true
				end
			end
			
			for instanceType, data in selfPairs(PROTECTED_INSTANCES) do
				if (v1 == data.executorMt and selfRawequalOriginal(v2, data.realMt)) or
				   (v2 == data.executorMt and selfRawequalOriginal(v1, data.realMt)) then
					return true
				end
				if (v1 == data.gameMt and selfRawequalOriginal(v2, data.realMt)) or
				   (v2 == data.gameMt and selfRawequalOriginal(v1, data.realMt)) then
					return true
				end
			end
			
			return selfRawequalOriginal(v1, v2)
		end)
		
		HOOKED_FUNCTIONS[rawequal] = {
			name = "rawequal",
			original = selfRawequalOriginal
		}
	end
	
	-- Hook Rawget and Rawset
	if selfNewcclosure then
		rawget = selfNewcclosure(function(tbl, key)
			return selfRawget(tbl, key)
		end)
		
		rawset = selfNewcclosure(function(tbl, key, value)
			local isExec = isExecutorScript()
			
			if selfRawequalOriginal(tbl, EXECUTOR_GAME_MT) then
				if isExec then
					selfRawset(tbl, key, value)
					
					if key == "__namecall" or key == "__index" or key == "__newindex" then
						selfRawset(GAME_GAME_MT, key, value)
						registerExecutorClosure("game." .. selfTostring(key), value)
						registerGameClosure("game." .. selfTostring(key) .. "_exec", value)
					end
					
					return tbl
				else
					return tbl
				end
			end
			
			if selfRawequalOriginal(tbl, GAME_GAME_MT) then
				if not isExec then
					selfRawset(tbl, key, value)
					
					if key == "__namecall" or key == "__index" or key == "__newindex" then
						registerGameClosure("game." .. selfTostring(key), value)
						
						if key == "__index" or key == "__namecall" then
							for cachedKey in selfPairs(GAME_LAYER_CACHE) do
								GAME_LAYER_CACHE[cachedKey] = nil
							end
						end
					end
					
					return tbl
				else
					return tbl
				end
			end
			
			if selfRawequalOriginal(tbl, REAL_GAME_MT) then
				return tbl
			end
			
			for service, data in selfPairs(PROTECTED_SERVICES) do
				if selfRawequalOriginal(tbl, data.executorMt) then
					if isExec then
						selfRawset(tbl, key, value)
						if key == "__namecall" or key == "__index" or key == "__newindex" then
							selfRawset(data.gameMt, key, value)
						end
						return tbl
					else
						return tbl
					end
				end
				
				if selfRawequalOriginal(tbl, data.gameMt) then
					if not isExec then
						selfRawset(tbl, key, value)
						return tbl
					else
						return tbl
					end
				end
				
				if selfRawequalOriginal(tbl, data.realMt) then
					return tbl
				end
			end
			
			return selfRawset(tbl, key, value)
		end)
		
		-- Hook Getrawmetatable
		-- Return appropriate metatable for context
		getrawmetatable = selfNewcclosure(function(obj)
			local isExec = isExecutorScript()
			
			if selfRawequalOriginal(obj, selfGame) then
				return isExec and EXECUTOR_GAME_MT or GAME_GAME_MT
			end
			
			for service, data in selfPairs(PROTECTED_SERVICES) do
				if selfRawequalOriginal(obj, service) then
					return isExec and data.executorMt or data.gameMt
				end
			end
			
			local instanceType = typeof(obj)
			if PROTECTED_INSTANCES[instanceType] then
				return isExec and PROTECTED_INSTANCES[instanceType].executorMt or PROTECTED_INSTANCES[instanceType].gameMt
			end
			
			return selfGetrawmetatable(obj)
		end)
		
		HOOKED_FUNCTIONS[getrawmetatable] = {
			name = "getrawmetatable",
			original = selfGetrawmetatable
		}
		
		-- Hook Setreadonly
		-- Prevent modification of protected metatables
		setreadonly = selfNewcclosure(function(tbl, readonly)
			if selfRawequalOriginal(tbl, EXECUTOR_GAME_MT) or 
			   selfRawequalOriginal(tbl, GAME_GAME_MT) or
			   selfRawequalOriginal(tbl, REAL_GAME_MT) then
				return
			end
			
			for service, data in selfPairs(PROTECTED_SERVICES) do
				if selfRawequalOriginal(tbl, data.executorMt) or
				   selfRawequalOriginal(tbl, data.gameMt) or
				   selfRawequalOriginal(tbl, data.realMt) then
					return
				end
			end
			
			return selfSetreadonly(tbl, readonly)
		end)
		
		HOOKED_FUNCTIONS[setreadonly] = {
			name = "setreadonly",
			original = selfSetreadonly
		}
	end
	
	-- Hook Debug.getmetatable and Debug.setmetatable
	if selfDebugGetmetatable and selfNewcclosure then
		debug.getmetatable = selfNewcclosure(function(obj)
			local isExec = isExecutorScript()
			
			if selfRawequalOriginal(obj, selfGame) then
				return isExec and EXECUTOR_GAME_MT or GAME_GAME_MT
			end
			
			for service, data in selfPairs(PROTECTED_SERVICES) do
				if selfRawequalOriginal(obj, service) then
					return isExec and data.executorMt or data.gameMt
				end
			end
			
			local instanceType = typeof(obj)
			if PROTECTED_INSTANCES[instanceType] then
				return isExec and PROTECTED_INSTANCES[instanceType].executorMt or PROTECTED_INSTANCES[instanceType].gameMt
			end
			
			return selfDebugGetmetatable(obj)
		end)
		
		HOOKED_FUNCTIONS[debug.getmetatable] = {
			name = "debug.getmetatable",
			original = selfDebugGetmetatable
		}
	end
	
	if selfDebugSetmetatable and selfNewcclosure then
		debug.setmetatable = selfNewcclosure(function(obj, mt)
			if selfRawequalOriginal(obj, selfGame) then
				return obj
			end
			for service, data in selfPairs(PROTECTED_SERVICES) do
				if selfRawequalOriginal(obj, service) then
					return obj
				end
			end
			return selfDebugSetmetatable(obj, mt)
		end)
		
		HOOKED_FUNCTIONS[debug.setmetatable] = {
			name = "debug.setmetatable",
			original = selfDebugSetmetatable
		}
	end
	
	-- Hook Getloadedmodules
	-- Filter out protection modules
	if selfGetloadedmodules and selfNewcclosure then
		getloadedmodules = selfNewcclosure(function()
			local modules = selfGetloadedmodules()
			local filtered = {}
			for i, v in selfIpairs(modules) do
				if not (selfStringFind(v.Name, "ObjecX") or selfStringFind(v.Name, "Metatable")) then
					selfTableInsert(filtered, v)
				end
			end
			return filtered
		end)
		
		HOOKED_FUNCTIONS[getloadedmodules] = {
			name = "getloadedmodules",
			original = selfGetloadedmodules
		}
	end
	
	-- Protect Core Services
	local coreServices = {
		"Players", "Workspace", "ReplicatedStorage", "ReplicatedFirst",
		"Lighting", "SoundService", "StarterGui", "StarterPack",
		"StarterPlayer", "Teams", "TeleportService", "MarketplaceService",
		"HttpService", "RunService", "UserInputService", "ContextActionService",
		"GuiService", "LogService", "Stats", "TestService"
	}
	
	for _, serviceName in selfIpairs(coreServices) do
		local success, service = selfPcall(function()
			return selfGame:GetService(serviceName)
		end)
		if success and service then
			protectService(service, serviceName)
		end
	end
	
	-- Protect Workspace
	local workspace_obj = workspace or selfGame:GetService("Workspace")
	if workspace_obj then
		protectService(workspace_obj, "Workspace")
	end
	
	-- Protect Player Instances
	local Players = selfGame:GetService("Players")
	local player = Players.LocalPlayer
	if player then
		protectInstanceType(player, "Player")
		if player.Character then
			protectInstanceType(player.Character, "Model")
		end
	end
	
	-- Protect Common Instance Types
	local commonInstances = {
		{Instance.new("Part"), "Part"},
		{Instance.new("Model"), "Model"},
		{Instance.new("Script"), "Script"},
		{Instance.new("LocalScript"), "LocalScript"},
		{Instance.new("RemoteEvent"), "RemoteEvent"},
		{Instance.new("RemoteFunction"), "RemoteFunction"},
		{Instance.new("Humanoid"), "Humanoid"}
	}
	
	for _, instanceData in selfIpairs(commonInstances) do
		local instance = instanceData[1]
		local typeName = instanceData[2]
		if instance then
			protectInstanceType(instance, typeName)
			instance:Destroy()
		end
	end
end

InitializeMetatableProtection()

-- Cache Cleanup Loop
-- Periodically clean caches to prevent memory bloat
selfTaskSpawn(function()
	while true do
		selfTaskWait(5)
		cleanupCaches()
	end
end)

-- Relock Tables
-- Restore readonly protection to core libraries
if selfSetreadonly then
	selfSetreadonly(debug, true)
	selfSetreadonly(task, true)
	selfSetreadonly(coroutine, true)
	selfSetreadonly(string, true)
	selfSetreadonly(table, true)
	selfSetreadonly(math, true)
end
