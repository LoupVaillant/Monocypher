#! /usr/bin/env lua

local lfs = require( "lfs" )

local all = {
	"#include \"../../../src/monocypher.h\"",
	"#include \"../../../src/optional/monocypher-ed25519.h\"",
	"#include <stdlib.h>",
	"int main() {",
}

local function AddExamples( man )
	for code in man:gmatch( "%.Bd[^\n]*\n(.-)%.Ed" ) do
		table.insert( all, "{" )
		table.insert( all, code )
		table.insert( all, "}" )
	end
end

local function AddDir( path )
	for file in lfs.dir( path ) do
		local attr = lfs.symlinkattributes( path .. "/" .. file )
		if file:match( "%.3monocypher$" ) and attr.mode == "file" then
			table.insert( all, "// " .. path .. "/" .. file )

			local f = assert( io.open( path .. "/" .. file, "r" ) )
			local contents = assert( f:read( "*all" ) )
			f:close()

			AddExamples( contents )

			table.insert( all, "" )
		end
	end
end

AddDir( "." )
AddDir( "optional" )

table.insert( all, "}" )

print( table.concat( all, "\n" ) )
