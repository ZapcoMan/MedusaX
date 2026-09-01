import axios from 'axios'
import qs from 'qs'
import {
  message
} from 'ant-design-vue';
import store from '@/store'

const config = require('../../faceConfig')
export const baseURL = config.basePath

// CSRF 令牌缓存与请求锁，避免并发场景下重复拉取令牌
let csrfToken = ''
let csrfTokenPromise = null

/**
 * 从 Cookie 中读取指定名称的值
 * 使用原生 document.cookie 解析，避免引入额外依赖
 */
function getCookie(name) {
  const prefix = name + '='
  const parts = document.cookie ? document.cookie.split(';') : []
  for (let i = 0; i < parts.length; i++) {
    const item = parts[i].trim()
    if (item.indexOf(prefix) === 0) {
      return decodeURIComponent(item.substring(prefix.length))
    }
  }
  return ''
}

// create an axios instance
const service = axios.create({
  baseURL,
  timeout: 10000, // request timeout
  withCredentials: true, // 携带 Cookie，CSRF 校验依赖令牌 Cookie
  xsrfCookieName: 'medusax_csrftoken',
  xsrfHeaderName: 'X-CSRFToken',
})

/**
 * 拉取 CSRF 令牌，后端通过 Set-Cookie 下发令牌并在响应体中返回同一份令牌
 * 使用请求锁保证并发调用时只发起一次真实请求
 */
function fetchCsrfToken() {
  if (csrfTokenPromise) {
    return csrfTokenPromise
  }
  csrfTokenPromise = service
    .get('/get_csrf_token/')
    .then(response => {
      const token = response && response.data && response.data.message ? response.data.message : ''
      csrfToken = token || getCookie('medusax_csrftoken')
      return csrfToken
    })
    .catch(() => {
      return ''
    })
    .then(token => {
      csrfTokenPromise = null
      return token
    })
  return csrfTokenPromise
}

// request interceptor
service.interceptors.request.use(
  config => {
    // GET 等幂等请求无需 CSRF 校验，仅对写操作注入令牌
    const method = (config.method || 'get').toLowerCase()
    if (method !== 'get' && method !== 'head' && method !== 'options') {
      const token = csrfToken || getCookie('medusax_csrftoken')
      if (token) {
        config.headers['X-CSRFToken'] = token
      }
    }
    return config
  },
  error => {
    // do something with request error
    console.log(error) // for debug
    return Promise.reject(error)
  }
)

// response interceptor
service.interceptors.response.use(
  /**
   * If you want to get http information such as headers or status
   * Please return  response => response
   */

  /**
   * Determine the request status by custom code
   * Here is just an example
   * You can also judge the status by HTTP Status Code
   */
  response => {
    if (response.headers.verificationcodekey) {
      store.commit("UserStore/setVerificationcodekey", response.headers.verificationcodekey)
    }
    const res = response.data
    // console.log(message)
    // if the custom code is not 0, it is judged as an error.
    // if (res.code !== 0) {
    // Message.error(res.message || 'Error')
    // 50008: Illegal token; 50012: Other clients logged in; 50014: Token expired;
    // if (res.code === 50008 || res.code === 50012 || res.code === 50014) {
    //   // to re-login
    //   MessageBox.confirm(
    //     'You have been logged out, you can cancel to stay on this page, or log in again',
    //     'Confirm logout',
    //     {
    //       confirmButtonText: 'Re-Login',
    //       cancelButtonText: 'Cancel',
    //       type: 'warning'
    //     }
    //   ).then(() => {
    //     store.dispatch('user/resetToken').then(() => {
    //       location.reload()
    //     })
    //   })
    // }
    //   return Promise.reject(new Error(res.message || 'Error'))
    // } else {
    return res
    // }
  },
  error => {
    // CSRF 令牌过期或缺失时，自动重新拉取令牌并重试一次，避免用户操作被 403 中断
    const response = error && error.response
    const originalRequest = error && error.config
    const data = response && response.data
    const isCsrfError =
      response &&
      response.status === 403 &&
      data &&
      data.code === 403

    if (isCsrfError && originalRequest && !originalRequest.__csrfRetry) {
      originalRequest.__csrfRetry = true
      csrfToken = '' // 丢弃失效令牌
      return fetchCsrfToken().then(token => {
        if (token) {
          originalRequest.headers['X-CSRFToken'] = token
        }
        return service.request(originalRequest)
      })
    }

    console.log('err' + error) // for debug
    message.error(error.message)

    return Promise.reject(error)
  }
)

export function get(url, params, config) {
  return new Promise((resolve, reject) => {
    service
      .get(url, {
        params: params,
        ...config
      })
      .then(response => {
        resolve(response)
      })
      .catch(err => {
        reject(err)
      })
  })
}
export function getParams(url, params, config) {
  return new Promise((resolve, reject) => {
    service
      .get(url, {
        params: qs.stringify(params),
        ...config
      })
      .then(response => {
        resolve(response)
      })
      .catch(err => {
        reject(err)
      })
  })
}

export function post(url, params, config) {
  return new Promise((resolve, reject) => {
    service
      .post(url, params, {
        ...config
      })
      .then(response => {
        resolve(response)
      })
      .catch(err => {
        reject(err)
      })
  })
}

export function postAcction(url, params, config) {
  return new Promise((resolve, reject) => {
    service
      .post(url, qs.stringify(params), {
        ...config
      })
      .then(response => {
        resolve(response)
      })
      .catch(err => {
        reject(err)
      })
  })
}

export function postDownload(url, params, config) {
  return new Promise((resolve, reject) => {
    service
      .post(url, params, {
        ...config,
        responseType: 'blob'
      })
      .then(response => {
        resolve(response)
      })
      .catch(err => {
        reject(err)
      })
  })
}
export function postParams(url, params, config) {
  return new Promise((resolve, reject) => {
    service
      .post(url, qs.stringify(params), {
        ...config
      })
      .then(response => {
        resolve(response)
      })
      .catch(err => {
        reject(err)
      })
  })
}

// 应用启动时预取一次 CSRF 令牌，确保首个写操作即可携带令牌
fetchCsrfToken()

export default service
export { fetchCsrfToken }