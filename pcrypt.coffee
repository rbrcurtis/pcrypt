#!/usr/bin/env /usr/local/bin/coffee

util = require 'util'

crypto = require 'crypto'

global.log = (message, obj = null, depth = 1) -> util.log "#{message}" + if obj then " : "+util.inspect obj, null, depth else ""

module.exports = class Hasher
	
	saltLength: 24

	createSalt: ->
		chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz!@#%^&*()_+-=;':\"{}[]\|<>?,./"
		str = ""
		i = 0
		
		while i < @saltLength
			num = Math.floor(Math.random() * chars.length)
			str += chars.substring(num, num + 1)
			i++
		
		return str
	
	
	hashPassword: (password, passes = 10, salt = null) ->
		if m = password.match /\$([0-9]+)\$(.{24})\$([a-z0-9]{64})/
			if +m[1] is passes
				return password
			else if +m[1] > passes
				throw "new number of passes must be greater than current, #{m[1]} vs #{passes}"
			else
				prevPasses = m[1]
				salt = m[2]
				password = m[3]
				return "$#{passes}$#{salt}$#{@_hash password, passes, prevPasses}"
				
		if salt and salt.length isnt @saltLength then throw "salt must be length #{@saltLength}"
		unless salt then salt = @createSalt()
		password = salt+password
		return "$#{passes}$#{salt}$#{@_hash password, passes, prevPasses}"
			


	_hash: (pass, passesLog2, prevPassesLog2 = 0) ->
		hash = (str) -> h = crypto.createHash 'sha256';h.update(str, 'utf8');return h.digest('hex')
		for j in [(Math.pow 2, prevPassesLog2)...(Math.pow 2, passesLog2)]
			pass = hash pass
		return pass
		
	verify: (plaintext, encrypted) ->
		unless m = encrypted.match /\$([0-9]+)\$(.{24})\$([a-z0-9]{64})/
			throw "encrypted version is not valid"
		passes = m[1]
		salt = m[2]
		password = m[3]
		return "$#{passes}$#{salt}$#{@_hash salt+plaintext, passes}" is encrypted


hp = new Hasher()

pass = '123'

start = new Date().getTime()
hashed = hp.hashPassword pass, process.argv[2]
unless hp.verify pass, hashed then throw new "didnt match for "+process.argv[2]
end = new Date().getTime()
console.log 'time', (end-start)
