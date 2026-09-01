<template>
  <div class="issue-task-page">
    <Card :name="'任务下发'" :bodyStyle="bodyStyle">
      <a-form :label-col="{ span: 4 }" :wrapper-col="{ span: 18 }">
        <a-form-item label="目标 URL">
          <a-input v-model="form.url" placeholder="请输入扫描目标，例如 www.example.com" @pressEnter="handleSubmit"/>
          <div class="form-tip">支持 IP / 域名 / URL 格式，一次下发一个目标</div>
        </a-form-item>
        <a-form-item label="扫描模块">
          <a-select v-model="form.module" style="width: 100%" placeholder="默认 all（全部插件）">
            <a-select-option v-for="m in modules" :key="m" :value="m">{{ m }}</a-select-option>
          </a-select>
          <div class="form-tip">all 表示使用全部已初始化插件，也可指定单个插件名</div>
        </a-form-item>
        <a-form-item label="并发线程">
          <a-row>
            <a-col :span="16">
              <a-slider :min="1" :max="50" v-model="form.process"/>
            </a-col>
            <a-col :span="4">
              <a-input-number :min="1" :max="50" v-model="form.process" style="width: 90px"/>
            </a-col>
          </a-row>
        </a-form-item>
        <a-form-item label="代理地址">
          <a-input v-model="form.proxy" placeholder="例如 127.0.0.1:8080，留空则不使用代理"/>
        </a-form-item>
        <a-form-item label="自定义请求头">
          <codemirror
            v-model="form.header"
            :options="{mode: 'text/plain', lineNumbers: true, theme: 'base16-light'}"
          />
          <div class="form-tip">每行一个，格式为 key: value，留空则使用默认请求头</div>
        </a-form-item>
        <a-form-item :wrapper-col="{ span: 18, offset: 4 }">
          <a-button type="primary" :loading="submitting" @click="handleSubmit">下发扫描任务</a-button>
          <a-button style="margin-left: 12px" @click="handleReset">重置</a-button>
        </a-form-item>
      </a-form>
    </Card>
    <Card :name="'参数说明'" :bodyStyle="bodyStyle">
      <a-collapse :bordered="false">
        <a-collapse-panel header="扫描模块如何选择？" key="1">
          <p class="help-text">模块名称与插件文件对应，选择 all 会遍历当前已初始化的全部 YAML 插件；
            指定单个模块时仅对该模块执行检测，适合定向验证。</p>
        </a-collapse-panel>
        <a-collapse-panel header="并发线程的作用？" key="2">
          <p class="help-text">并发线程数决定同一时刻发起的 HTTP 探测数量，越大扫描越快，
            但对目标与本地资源压力越大，建议根据目标承受能力在 1 ~ 50 之间调节。</p>
        </a-collapse-panel>
        <a-collapse-panel header="自定义请求头格式？" key="3">
          <p class="help-text">每行一个请求头，例如：<br/><code>User-Agent: Mozilla/5.0</code><br/>
            <code>Cookie: session=abc</code><br/>留空时平台会使用默认请求头配置。</p>
        </a-collapse-panel>
        <a-collapse-panel header="任务下发后如何查看结果？" key="4">
          <p class="help-text">任务下发成功后会自动跳转到「站点扫描」页面，可在任务列表中查看扫描进度，
            点击任务即可查看命中漏洞、端口信息与子域名探测结果，并支持导出 Word 报告。</p>
        </a-collapse-panel>
      </a-collapse>
    </Card>
  </div>
</template>

<script>
import Card from '@/components/Card/Card.vue'
import { mapGetters } from 'vuex'
import { OverallMixins } from '@/js/Mixins/OverallMixins.js'
import { codemirror } from 'vue-codemirror'

// import base style
import 'codemirror/lib/codemirror.css'
import 'codemirror/theme/base16-light.css'

export default {
  name: 'IssueTask',
  mixins: [OverallMixins],
  components: { Card, codemirror },
  computed: {
    ...mapGetters({
      token: 'UserStore/token'
    })
  },
  data () {
    return {
      bodyStyle: {
        borderTop: '3px solid #177DDC',
        borderBottom: '0px'
      },
      submitting: false,
      modules: ['all', 'test', 'BIG-IP', 'WebLogic', 'Struts2', 'Spring', 'Nginx', 'Apache'],
      form: {
        url: '',
        module: 'all',
        process: 5,
        proxy: '',
        header: ''
      }
    }
  },
  methods: {
    handleReset () {
      this.form = {
        url: '',
        module: 'all',
        process: 5,
        proxy: '',
        header: ''
      }
    },
    handleSubmit () {
      if (!this.form.url || !this.form.url.trim()) {
        this.$message.warn('请输入扫描目标！')
        return
      }
      if (this.submitting) return
      this.submitting = true
      const params = {
        url: this.form.url.trim(),
        token: this.token,
        process: this.form.process,
        module: this.form.module || 'all',
        header: this.form.header || '',
        proxy: this.form.proxy || ''
      }
      this.$api.scanning(params).then(res => {
        if (res.code === 200) {
          this.$message.success('任务下发成功，任务ID：' + res.message.active_scan_id)
          setTimeout(() => {
            this.$router.push('/layout/siteInformation')
          }, 600)
        } else {
          this.$message.error(res.message || '任务下发失败')
        }
        this.submitting = false
      }).catch(() => {
        this.$message.error('网络异常，任务下发失败')
        this.submitting = false
      })
    }
  }
}
</script>

<style lang="scss" scoped>
.issue-task-page {
  padding: 12px;
  background: #141414;
  min-height: 100%;
}
.form-tip {
  color: #8C8C8C;
  font-size: 12px;
  margin-top: 4px;
  line-height: 18px;
}
.help-text {
  color: #BFBFBF;
  font-size: 14px;
  line-height: 24px;
  margin-bottom: 0;
}
::v-deep .CodeMirror {
  height: auto !important;
  max-height: 220px;
  border: 1px solid #303030;
}
::v-deep .ant-collapse {
  background: transparent;
}
::v-deep .ant-collapse-header {
  color: #BFBFBF !important;
}
::v-deep .ant-form-item-label label {
  color: #BFBFBF;
}
::v-deep .ant-select-selection,
::v-deep .ant-input,
::v-deep .ant-input-number {
  background: #1F1F1F;
  border-color: #303030;
  color: #FFFFFF;
}
::v-deep .ant-select-arrow {
  color: #8C8C8C;
}
</style>
