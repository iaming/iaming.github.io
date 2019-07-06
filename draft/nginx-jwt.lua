local jwt = require "resty.jwt"
local validators = require "resty.jwt-validators"

local _M = {}

function _M.auth(claim_specs)
    -- get token, header > request > cookie
    local jwt_token = nil
    local auth_header = ngx.var.http_Authorization
    if auth_header == nil then
        ngx.log(ngx.DEBUG,"Authorization header中无token")
        -- get token from quest
        jwt_token = ngx.var.arg_jwt
        if jwt_token == nil then
            -- Query中无token，从Cookies中获取
            jwt_token = ngx.var.cookie_jwt
            ngx.log(ngx.DEBUG,"Query中无token，从Cookies中获取")
            if jwt_token == nil then
                ngx.log(ngx.WARN, "Cookies无token，401返回")
                ngx.exit(ngx.HTTP_UNAUTHORIZED)
            end
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

    ngx.log(ngx.DEBUG, "获取到jwt_token，开始验证...")

    if claim_specs == nil then
        claim_spec = {
            leeway = validators.set_system_leeway(ngx.var.jwt_duration),
            iat = validators.is_at(),
            __jwt = validators.require_one_of({"lvl", "registed"})
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
        local exp_remain_time = payload["exp"] - ngx.now()
        ngx.log(ngx.DEBUG, "exp_remain:" .. exp_remain_time)
        if exp_remain_time < 300 and exp_remain_time > 0 then
            -- refresh jwt
            ngx.log(ngx.DEBUG, "Refresh token")
            local rat = ngx.now()
            local exp = rat + ngx.var.jwt_duration
            payload["iat"] = rat
            payload["exp"] = exp
            local jwt_token = jwt:sign(
                ngx.var.jwt_secret,
                {
                    header = jwt_obj["header"],
                    payload = payload
                }
            )
            ngx.header['Set-Cookie'] = "jwt=" .. jwt_token .. "; path=/; Expires=" .. ngx.cookie_time(exp)
            ngx.header['Authorization'] = "Bearer " .. jwt_token
        end
    end

end

-- payload增加uid（用户id）,lvl（等级），jti，lat(登录时间)
function _M.login(uid)
    local lat = ngx.now()
    local exp = lat + ngx.var.jwt_duration
    local jwt_token = jwt:sign(
        ngx.var.jwt_secret,
        {
            header = {typ = "JWT", alg = "HS256"},
            payload = {
                uid = uid,
                lvl = "registed",
                lat = lat,
                iat = lat,
                exp = exp
            }
        }
    )
    ngx.header['Set-Cookie'] = "jwt=" .. jwt_token .. "; path=/; Expires=" .. ngx.cookie_time(exp)
    ngx.header['Authorization'] = "Bearer " .. jwt_token
    ngx.say("{\"content\":\"" .. jwt_token .. "\"}")
end

function _M.problem(problem_status,problem_code,problem_message)
    ngx.status = problem_status
    ngx.say('{"type": "/problems/'.. problem_code .. '", "title": "'.. problem_code .. '",' .. '"status": ' .. problem_status ..',"message": "' .. problem_message ..'","timestamp": "' .. ngx.time() ..'"}')
    ngx.exit(ngx.HTTP_OK)
end

return _M