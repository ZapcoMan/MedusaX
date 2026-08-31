<template>
  <Win98 ref="win98" @Ok="handleRegister" :task="`Register`">
    <a-row
      type="flex"
      justify="center"
      align="top"
      style="height:100%"
      :gutter="[
     16, { xs: 4, sm: 8, md: 12, lg: 16 }
    ]"
    >
      <a-col :span="24">
        <a-form :form="form" :labelCol="{xs:8,lg:6}" :wrapper-col="{ span: 14,offset:1 }">
          <a-form-item label="Key">
            <a-input
              v-decorator="[
            'key',
            { rules: [{ required: true, message: 'Key Cannot be empty' }] }
          ]"
            >
              <a-icon slot="prefix" type="key" style="color: rgba(0, 0, 0, 0.25)" />
            </a-input>
          </a-form-item>

          <a-form-item label="UserName">
            <a-input
              v-decorator="[
            'username',
            { rules: [{ required: true, message: 'UserName Cannot be empty' }] }
          ]"
            >
              <a-icon slot="prefix" type="user" style="color: rgba(0, 0, 0, 0.25)" />
            </a-input>
          </a-form-item>
          <a-form-item label="show_name">
            <a-input
              v-decorator="[
            'show_name',
            { rules: [{ required: true, message: 'show_name  Cannot be empty' }] }
          ]"
            >
              <a-icon slot="prefix" type="user" style="color: rgba(0, 0, 0, 0.25)" />
            </a-input>
          </a-form-item>
          <a-form-item label="E-mail">
            <a-input
              v-decorator="[
            'email',
            { rules: [{ required: true, message: 'E-mail  Cannot be empty' },{type:'email'}] }
          ]"
            >
              <a-icon slot="prefix" type="mail" style="color: rgba(0, 0, 0, 0.25)" />
            </a-input>
          </a-form-item>
          <a-form-item label="Password">
            <a-input
              type="password"
              v-decorator="[
            'passwd',
            { rules: [{ required: true, message: 'Password Cannot be empty' },{validator:(rule, value, callback)=>this.handlePassWord(rule, value, callback)}] }
          ]"
            >
              <a-icon slot="prefix" type="unlock" style="color: rgba(0, 0, 0, 0.25)" />
            </a-input>
          </a-form-item>
          <a-form-item label="ConfirmPassword">
            <a-input
              type="password"
              v-decorator="[
            'confirmpasswd',
            { rules: [{ required: true, message: 'ConfirmPassword  Cannot be empty' },{validator:(rule, value, callback)=>this.handlePassWord(rule, value, callback)}] }
          ]"
            >
              <a-icon slot="prefix" type="unlock" style="color: rgba(0, 0, 0, 0.25)" />
            </a-input>
          </a-form-item>
          <a-form-item label="VerificationCode" :wrapper-col="{ span: 14,offset:1 }">
            <a-col :span="12">
              <a-input
                v-decorator="[
            'verificationCode',
            { rules: [{ required: true, message: 'VerificationCode  Cannot be empty' }] }
          ]"
              ></a-input>
            </a-col>
            <a-col :span="10" :offset="2">
              <VerificationCode ref="verificationCode" style="height: 30px;" />
            </a-col>
          </a-form-item>
        </a-form>
      </a-col>
    </a-row>
  </Win98>
</template>

<script>
import Win98 from "@/components/Win98/Win98.vue"
import { mapGetters } from "vuex";
import VerificationCode from '@/components/VerificationCode/VerificationCode.vue'
export default {
  data () {
    return {
      form: this.$form.createForm(this, { name: 'form' }),
      checkPasswd: false,
      checkConfirmPasswd: false
    }
  },
  components: {
    Win98,
    VerificationCode
  },
  computed: {
    ...mapGetters({
      verificationcodekey: "UserStore/verificationcodekey",
      token: "UserStore/token",
      userinfo: "UserStore/userinfo"
    }),
  },
  methods: {
    handleRegister () {
      const _this = this
      _this.form.validateFields((err, values) => {
        if (!err) {
          const params = {
            key: values.key,
            show_name: values.show_name,
            username: values.username,
            passwd: values.passwd,
            email: values.email,
            verification_code_key: _this.verificationcodekey,
            verification_code: values.verificationCode,
          }
          _this.$api.registered(params).then((res) => {
            if (res.code == 200) {
              const success = {
                title: 'Success',
                message: 'register has success:是否跳转到登录页?'
              }
              const callback = () => {
                this.$router.push("/login");
              }
              _this.$refs.win98.handleErrShow(success, callback)
            } else {
              const err = {
                title: 'Err',
                message: `register has failed:${res.message}`
              }
              _this.$refs.win98.handleErrShow(err)
              _this.$refs.verificationCode.handleVerificationCode()
            }
          });
        }
        else {
          const warn = {
            title: 'Warn',
            message: 'Please complete all form items'
          }
          _this.$refs.win98.handleErrShow(warn)
        }
      })
    },
    handlePassWord (rule, value, callback) {
      const _this = this
      const form = _this.form.getFieldsValue()
      if (value == undefined) {
        callback('Is Null')
      }
      else {
        if (rule.field == 'passwd') {
          if (value == form.confirmpasswd) {
            _this.checkPasswd = true
            if (_this.checkConfirmPasswd && _this.checkPasswd) {
              _this.checkConfirmPasswd = false
              _this.checkPasswd = false
            }
            else {
              _this.form.validateFields(["confirmpasswd"])
            }
            callback()
          }
          else {
            _this.checkPasswd = false
            callback('The two passwords are inconsistent')
          }
        }
        else if (rule.field == 'confirmpasswd') {
          if (value == form.passwd) {
            _this.checkConfirmPasswd = true
            if (_this.checkConfirmPasswd && _this.checkPasswd) {
              _this.checkConfirmPasswd = false
              _this.checkPasswd = false
            }
            else {
              _this.form.validateFields(["passwd"])
            }
            callback()
          }
          else {
            _this.checkConfirmPasswd = false
            callback('The two passwords are inconsistent')
          }
        }
      }

    }
  }
}
</script>

<style>
</style>