package org.example.antares.member.service.impl;

import com.alibaba.fastjson.JSON;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;
import org.example.antares.common.constant.RedisConstants;
import org.example.antares.common.domain.response.AppHttpCodeEnum;
import org.example.antares.common.domain.response.R;
import org.example.antares.common.exception.BusinessException;
import org.example.antares.common.utils.BeanCopyUtils;
import org.example.antares.common.utils.HttpUtils;
import org.example.antares.member.domain.entity.User;
import org.example.antares.member.domain.vo.GiteeUser;
import org.example.antares.member.domain.vo.SocialUser;
import org.example.antares.member.domain.vo.request.UserLoginVo;
import org.example.antares.member.domain.vo.request.UserRegisterVo;
import org.example.antares.member.domain.vo.request.UserUpdateVo;
import org.example.antares.member.domain.vo.response.UserInfoVo;
import org.example.antares.member.feign.ThirdPartFeignService;
import org.example.antares.member.mapper.UserMapper;
import org.example.antares.member.service.UserTagService;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;


import org.example.antares.member.service.UserService;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.example.antares.common.constant.SystemConstants.*;


@Service("antaresUserService")
@Slf4j
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    @Resource
    private StringRedisTemplate stringRedisTemplate;
    @Resource
    private ThirdPartFeignService thirdPartFeignService;
    @Resource
    private UserTagService userTagService;

    @Override
    public R sendCode(String dest, int type) {
        String redisCodeKey = (type == PHONE_CODE ? RedisConstants.CODE_SMS_CACHE_PREFIX : RedisConstants.MAIL_CODE_CACHE_PREFIX) + dest;
        String redisCode = stringRedisTemplate.opsForValue().get(redisCodeKey);
        //1、接口防刷
        //发送过验证码了
        if (!StringUtils.isEmpty(redisCode)) {
            //用当前时间减去存入redis的时间，判断用户手机号是否在60s内发送验证码
            long currentTime = Long.parseLong(redisCode.split("_")[1]);
            if (System.currentTimeMillis() - currentTime < 60000) {
                //60s内不能再发
                return R.error(AppHttpCodeEnum.CODE_EXCEPTION);
            }
        }

        //2、key的形式是prefix:phone，value是codeNum_系统时间
        int code = (int) ((Math.random() * 9 + 1) * 100000);
        log.info("{}", code);
        String codeNum = String.valueOf(code);
        String redisStorage = codeNum + "_" + System.currentTimeMillis();

        //存入redis，防止同一个手机号在60秒内再次发送验证码
        stringRedisTemplate.opsForValue().set(redisCodeKey, redisStorage,10, TimeUnit.MINUTES);

        if(type == PHONE_CODE){
            thirdPartFeignService.sendCode(dest, codeNum);
        } else if (type == MAIL_CODE) {
            thirdPartFeignService.sendMail(dest, codeNum);
        }
        return R.ok();
    }

    @Override
    public R register(UserRegisterVo vo) {
        //1、效验验证码
        String code = vo.getCode();

        //获取存入Redis里的验证码
        String redisCodeKey = RedisConstants.MAIL_CODE_CACHE_PREFIX + vo.getEmail();
        String redisCode = stringRedisTemplate.opsForValue().get(redisCodeKey);
        //获取redis中验证码并进行截取
        if (!StringUtils.isEmpty(redisCode) && code.equals(redisCode.split("_")[0])) {
            //删除验证码;令牌机制
            stringRedisTemplate.delete(redisCodeKey);
            //验证码通过，真正注册
            User user = new User();
            //检查邮箱是否唯一。感知异常，异常机制
            checkEmailUnique(user.getEmail());

            user.setEmail(vo.getEmail());
            //密码进行MD5加密
            BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
            String encode = bCryptPasswordEncoder.encode(vo.getPassword());
            user.setPassword(encode);

            //保存数据
            baseMapper.insert(user);
            user.setUsername(USERNAME_PREFIX + user.getUid());
            baseMapper.updateById(user);
            return R.ok();
        }
        return R.error(AppHttpCodeEnum.CODE_EXCEPTION);
    }

    @Override
    public R login(UserLoginVo vo, HttpSession session) {
        String account = vo.getAccount();
        String password = vo.getPassword();

        //1、去数据库查询 SELECT * FROM antares_user WHERE username = ? OR phone = ?
        User user = baseMapper.selectOne(new LambdaQueryWrapper<User>()
                .eq(User::getEmail, account).or().eq(User::getPhone, account));

        if (user == null) {
            //登录失败
            return R.error(AppHttpCodeEnum.ACCOUNT_NOT_EXIST);
        } else {
            //获取到数据库里的password
            String passwordCrypt = user.getPassword();
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            //进行密码匹配
            boolean matches = passwordEncoder.matches(password, passwordCrypt);
            if (matches) {
                //登录成功，获取当前用户的所有tags，并返回一个vo对象
                UserInfoVo userInfoVo = userToVo(user);

                session.setAttribute(LOGIN_USER, userInfoVo);
                return R.ok();
            } else {
                return R.error(AppHttpCodeEnum.WRONG_PASSWORD);
            }
        }
    }

    private UserInfoVo userToVo(User user) {
        UserInfoVo userInfoVo = BeanCopyUtils.copyBean(user, UserInfoVo.class);
        userInfoVo.setTags(userTagService.idsToTags(user.getTags()));
        return userInfoVo;
    }

    @Override
    public R oauthLogin(SocialUser socialUser) throws IOException {
        HashMap<String, String> param = new HashMap<>();
        param.put("access_token", socialUser.getAccess_token());
        HttpResponse response = null;
        try {
            response = HttpUtils.doGet("https://gitee.com", "/api/v5/user", "get", new HashMap<>(), param);
        } catch (Exception e) {
            throw new BusinessException(AppHttpCodeEnum.THIRD_PARTY_EXCEPTION);
        }

        //查询这个用户的gitee信息
        if(response.getStatusLine().getStatusCode() == 200){
            String userJson = EntityUtils.toString(response.getEntity());
            GiteeUser giteeUser = JSON.parseObject(userJson, GiteeUser.class);

            //具有登录和注册逻辑
            String socialId = giteeUser.getId();
            //1、判断当前社交用户是否已经登录过系统
            User user = baseMapper.selectOne(new LambdaQueryWrapper<User>()
                    .eq(User::getSocialUid, socialId));
            //这个用户已经注册过
            if (user != null) {
                //更新用户的访问令牌的时间和access_token
                User update = new User();
                update.setUid(user.getUid());
                update.setAccessToken(socialUser.getAccess_token());
                update.setExpiresIn(socialUser.getExpires_in());
                baseMapper.updateById(update);

                user.setAccessToken(socialUser.getAccess_token());
                user.setExpiresIn(socialUser.getExpires_in());
                return R.ok(user);
            } else {
                //2、没有查到当前社交用户对应的记录我们就需要注册一个
                User register = new User();

                register.setUsername(USERNAME_PREFIX + UUID.randomUUID());
                register.setAvatar(giteeUser.getAvatar_url());
                register.setSocialUid(giteeUser.getId());
                register.setAccessToken(socialUser.getAccess_token());
                register.setExpiresIn(socialUser.getExpires_in());

                //把用户信息插入到数据库中
                baseMapper.insert(register);
                return R.ok(register);
            }
        }
        return R.error(AppHttpCodeEnum.THIRD_PARTY_EXCEPTION);
    }

    @Override
    public R getCurrentUser(HttpSession session) {
        UserInfoVo loginUser = (UserInfoVo) session.getAttribute(LOGIN_USER);
        if(loginUser == null){
            throw new BusinessException(AppHttpCodeEnum.NOT_LOGIN);
        } else{
            return R.ok(loginUser);
        }
    }

    @Override
    public R updateCurrentUserInfo(UserUpdateVo updateVo, HttpSession session) {
        //如果是当前用户才可以更新
        UserInfoVo vo = (UserInfoVo)session.getAttribute(LOGIN_USER);
        if(vo == null){
            return R.error(AppHttpCodeEnum.NOT_LOGIN);
        }
        if(vo.getUid() == updateVo.getUid()) {
            //更新数据库
            User user = BeanCopyUtils.copyBean(updateVo, User.class);
            user.setTags(JSON.toJSONString(updateVo.getTags()));
            updateById(user);
            //更新session
            BeanCopyUtils.copyPropertiesIgnoreNull(updateVo, vo);
            vo.setTags(userTagService.idsToTags(updateVo.getTags()));
            session.setAttribute(LOGIN_USER, vo);
            return R.ok();
        }else {
            return R.error(AppHttpCodeEnum.NO_AUTH);
        }
    }

    @Override
    public void checkPhoneUnique(String phone) throws BusinessException {
        Integer phoneCount = baseMapper.selectCount(new LambdaQueryWrapper<User>().eq(User::getPhone, phone));
        if (phoneCount > 0) {
            throw new BusinessException(AppHttpCodeEnum.PHONE_EXIST);
        }
    }

    @Override
    public void checkUsernameUnique(String username) throws BusinessException {
        Integer usernameCount = baseMapper.selectCount(new LambdaQueryWrapper<User>().eq(User::getUsername, username));
        if (usernameCount > 0) {
            throw new BusinessException(AppHttpCodeEnum.USER_EXIST);
        }
    }

    @Override
    public void checkEmailUnique(String email) throws BusinessException {
        Integer emailCount = baseMapper.selectCount(new LambdaQueryWrapper<User>().eq(User::getEmail, email));
        if (emailCount > 0) {
            throw new BusinessException(AppHttpCodeEnum.USER_EXIST);
        }
    }
}