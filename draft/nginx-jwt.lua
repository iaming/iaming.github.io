local jwt = require "resty.jwt"
local validators = require "resty.jwt-validators"

local M = {}

function M.auth(claim_specs)
    -- get token, header > request > cookie
    local jwt_token = nil
    local auth_header = ngx.var.http_Authorization
    if auth_header == nil then
        -- get token from quest
        jwt_token = ngx.var.arg_jwt
        if jwt_token then
            ngx.log(ngx.DEBUG,"Query token exist")
            ngx.header['Set-Cookie'] = "jwt=" .. jwt_token
        else
            -- get token from cookie
            jwt_token = ngx.var.cookie_jwt
            ngx.log(ngx.DEBUG,"Cookie token exist")
        end

        if jwt_token == nil then
            ngx.log(ngx.WARN, "No Authorization header")
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
    else
        ngx.log(ngx.INFO, "Authorization: " .. auth_header)

        -- require Bearer token
        local _, _, auth_token = string.find(auth_header, "Bearer%s+(.+)")

        if auth_token == nil then
            ngx.log(ngx.WARN, "Missing token")
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
        else
            jwt_token = auth_token
        end
    end

    ngx.log(ngx.INFO, "jwt_token: " .. jwt_token)

    if claim_specs == nil then
        claim_spec = {
            leeway = validators.set_system_leeway(900),
            iat = validators.is_at(),
            __jwt = validators.require_one_of({ "foo", "bar" })
        }
    end

    -- require valid JWT
    local jwt_obj = jwt:verify(ngx.var.jwt_secret, jwt_token, claim_specs)
    if not jwt_obj["verified"] then
        ngx.log(ngx.WARN, "Invalid token: ".. jwt_obj.reason)
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local payload = jwt_obj["payload"]
    if payload.exp ~= nil then
        local exp_remain_times = payload.exp - system_clock()
        if exp_remain_times < 300 and exp_remain_times > 0 then
            -- refresh jwt
            ngx.log(ngx.DEBUG, "Refresh token")
            payload["iat"] = system_clock()
            payload["exp"] = system_clock() + 900
            local jwt_token = jwt:sign(
                ngx.var.jwt_secret,
                {
                    header=cjson.encode(jwt_obj["header"]),
                    payload=cjson.encode(payload)
                }
            )
            ngx.header['Set-Cookie'] = "jwt=" .. jwt_token
            ngx.header['Authorization'] = "Bearer " .. jwt_token
        end
    end

end

return M