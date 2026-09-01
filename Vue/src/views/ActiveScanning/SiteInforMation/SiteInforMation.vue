<template>
  <div class="site-info-page">
    <a-row :gutter="12">
      <a-col :xs="24" :lg="10">
        <Card :name="'扫描任务列表'" :bodyStyle="bodyStyle">
          <div class="toolbar">
            <a-radio-group v-model="statusFilter" size="small" @change="handleFilterChange">
              <a-radio-button value="all">全部</a-radio-button>
              <a-radio-button value="0">扫描中</a-radio-button>
              <a-radio-button value="1">已完成</a-radio-button>
            </a-radio-group>
            <a-button size="small" type="primary" icon="reload" @click="handleRefresh">刷新</a-button>
          </div>
          <a-table
            size="small"
            :columns="taskColumns"
            :data-source="taskList"
            :pagination="{ pageSize: 8, showTotal: t => `共 ${t} 条` }"
            row-key="active_scan_id"
            :row-class-name="rowClassName"
            :custom-row="customTaskRow"
            :loading="taskLoading"
          >
            <template slot="status" slot-scope="text">
              <a-badge v-if="text === '0'" status="processing" text="扫描中"/>
              <a-badge v-else-if="text === '1'" status="success" text="已完成"/>
              <a-badge v-else status="default" :text="'未知(' + text + ')'"/>
            </template>
          </a-table>
        </Card>
      </a-col>
      <a-col :xs="24" :lg="14">
        <Card :name="'漏洞列表' + (currentTask ? ' - ' + currentTask.url : '')" :bodyStyle="bodyStyle">
          <template slot="extraCard">
            <a-button size="small" type="danger" icon="file-word"
                      :loading="generating" :disabled="!currentTask" @click="handleGenerateWord">生成报告</a-button>
          </template>
          <a-table
            size="small"
            :columns="vulColumns"
            :data-source="vulList"
            :pagination="{ pageSize: 8, showTotal: t => `共 ${t} 条` }"
            row-key="scan_info_id"
            :custom-row="customVulRow"
            :loading="vulLoading"
          >
            <template slot="rank" slot-scope="text">
              <a-tag :color="rankColor(text)">{{ text }}</a-tag>
            </template>
          </a-table>
        </Card>
      </a-col>
    </a-row>

    <Card :name="'扩展信息'" :bodyStyle="bodyStyle" v-if="currentTask">
      <a-tabs default-active-key="port">
        <a-tab-pane key="port" tab="端口扫描">
          <a-table
            size="small"
            :columns="portColumns"
            :data-source="portList"
            :pagination="false"
            :loading="portLoading"
          />
        </a-tab-pane>
        <a-tab-pane key="subdomain" tab="子域名探测">
          <a-table
            size="small"
            :columns="subdomainColumns"
            :data-source="subdomainList"
            :pagination="false"
            :loading="subdomainLoading"
          />
        </a-tab-pane>
      </a-tabs>
    </Card>

    <a-drawer
      title="漏洞详情"
      :width="680"
      :visible="detailVisible"
      :body-style="{padding: '12px', background: '#1F1F1F'}"
      @close="detailVisible = false"
    >
      <template v-if="detail">
        <a-descriptions :column="1" size="small" bordered style="margin-bottom: 12px;">
          <a-descriptions-item label="漏洞名称">{{ detail.name }}</a-descriptions-item>
          <a-descriptions-item label="漏洞等级">
            <a-tag :color="rankColor(detail.rank)">{{ detail.rank }}</a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="CVE 编号">{{ detail.number || '无' }}</a-descriptions-item>
          <a-descriptions-item label="影响组件">{{ detail.affects || '无' }}</a-descriptions-item>
          <a-descriptions-item label="影响版本">{{ detail.version || '无' }}</a-descriptions-item>
          <a-descriptions-item label="描述">{{ detail.desc_content || '无' }}</a-descriptions-item>
          <a-descriptions-item label="修复建议">{{ detail.suggest || '无' }}</a-descriptions-item>
        </a-descriptions>
        <a-tabs default-active-key="reqHeader" size="small">
          <a-tab-pane key="reqHeader" tab="请求头">
            <pre class="pack-pre">{{ decodeB64(detail.request_headers) }}</pre>
          </a-tab-pane>
          <a-tab-pane key="reqBody" tab="请求体">
            <pre class="pack-pre">{{ decodeB64(detail.request_body) }}</pre>
          </a-tab-pane>
          <a-tab-pane key="resHeader" tab="响应头">
            <pre class="pack-pre">{{ decodeB64(detail.response_headers) }}</pre>
          </a-tab-pane>
          <a-tab-pane key="resBody" tab="响应体">
            <pre class="pack-pre">{{ decodeB64(detail.response_text) }}</pre>
          </a-tab-pane>
        </a-tabs>
      </template>
    </a-drawer>
  </div>
</template>

<script>
import Card from '@/components/Card/Card.vue'
import { mapGetters } from 'vuex'
import { OverallMixins } from '@/js/Mixins/OverallMixins.js'

export default {
  name: 'SiteInforMation',
  mixins: [OverallMixins],
  components: { Card },
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
      statusFilter: 'all',
      taskLoading: false,
      taskList: [],
      currentTask: null,
      vulLoading: false,
      vulList: [],
      portLoading: false,
      portList: [],
      subdomainLoading: false,
      subdomainList: [],
      detailVisible: false,
      detail: null,
      generating: false,
      pollTimer: null,
      taskColumns: [
        { title: '任务ID', dataIndex: 'active_scan_id', width: 70 },
        { title: '目标', dataIndex: 'url', ellipsis: true },
        { title: '状态', dataIndex: 'status', width: 90, scopedSlots: { customRender: 'status' } },
        { title: '模块', dataIndex: 'module', width: 110, ellipsis: true },
        { title: '线程', dataIndex: 'process', width: 60 },
        { title: '创建时间', dataIndex: 'creation_time', width: 110, customRender: t => this.moment.unix(Number(t)).format('MM-DD HH:mm') }
      ],
      vulColumns: [
        { title: 'ID', dataIndex: 'scan_info_id', width: 60 },
        { title: '漏洞名称', dataIndex: 'name', ellipsis: true },
        { title: '等级', dataIndex: 'rank', width: 80, scopedSlots: { customRender: 'rank' } }
      ],
      portColumns: [
        { title: '端口', dataIndex: 'port', width: 80 },
        { title: '服务', dataIndex: 'service', width: 120 },
        { title: '状态', dataIndex: 'status', width: 80 },
        { title: '协议', dataIndex: 'protocol', width: 80 }
      ],
      subdomainColumns: [
        { title: '子域名', dataIndex: 'subdomain', ellipsis: true },
        { title: '解析地址', dataIndex: 'address', ellipsis: true }
      ]
    }
  },
  mounted () {
    this.handleRefresh()
    this.pollTimer = setInterval(() => {
      if (this.taskList.some(t => t.status === '0')) this.handleRefresh(false)
    }, 5000)
  },
  beforeDestroy () {
    if (this.pollTimer) clearInterval(this.pollTimer)
  },
  methods: {
    rowClassName (record) {
      return this.currentTask && this.currentTask.active_scan_id === record.active_scan_id ? 'row-selected' : ''
    },
    customTaskRow (record) {
      return {
        on: {
          click: () => this.handleSelectTask(record)
        }
      }
    },
    customVulRow (record) {
      return {
        on: {
          click: () => this.handleShowDetail(record)
        }
      }
    },
    handleFilterChange () {
      if (this.statusFilter === 'all') {
        this.taskList = this.allTaskList
      } else {
        this.taskList = this.allTaskList.filter(t => t.status === this.statusFilter)
      }
    },
    handleRefresh (showLoading = true) {
      if (showLoading) this.taskLoading = true
      this.$api.list_query({ token: this.token }).then(res => {
        if (res.code === 200) {
          this.allTaskList = res.message || []
          this.handleFilterChange()
          if (!this.currentTask && this.allTaskList.length > 0) {
            this.handleSelectTask(this.allTaskList[0])
          } else if (this.currentTask) {
            const fresh = this.allTaskList.find(t => t.active_scan_id === this.currentTask.active_scan_id)
            if (fresh) {
              this.currentTask = fresh
              if (fresh.status === '1') this.loadVulList()
            }
          }
        }
        if (showLoading) this.taskLoading = false
      }).catch(() => {
        if (showLoading) this.taskLoading = false
        this.$message.error('任务列表获取失败')
      })
    },
    handleSelectTask (task) {
      this.currentTask = task
      this.loadVulList()
      this.loadPortList()
      this.loadSubdomainList()
    },
    loadVulList () {
      this.vulLoading = true
      this.$api.imfomation_query({ token: this.token, active_scan_id: this.currentTask.active_scan_id }).then(res => {
        this.vulLoading = false
        if (res.code === 200) {
          this.vulList = res.message || []
        } else {
          this.vulList = []
        }
      }).catch(() => {
        this.vulLoading = false
        this.vulList = []
      })
    },
    loadPortList () {
      this.portLoading = true
      this.$api.port_information({ token: this.token, active_scan_id: this.currentTask.active_scan_id }).then(res => {
        this.portLoading = false
        if (res.code === 200 && Array.isArray(res.message)) {
          this.portList = res.message
        } else {
          this.portList = []
        }
      }).catch(() => {
        this.portLoading = false
        this.portList = []
      })
    },
    loadSubdomainList () {
      this.subdomainLoading = true
      this.$api.subdomain_query({ token: this.token, active_scan_id: this.currentTask.active_scan_id }).then(res => {
        this.subdomainLoading = false
        if (res.code === 200 && Array.isArray(res.message)) {
          this.subdomainList = res.message
        } else {
          this.subdomainList = []
        }
      }).catch(() => {
        this.subdomainLoading = false
        this.subdomainList = []
      })
    },
    handleShowDetail (record) {
      this.$api.medusa_query({ token: this.token, scan_info_id: record.scan_info_id }).then(res => {
        if (res.code === 200 && Array.isArray(res.message) && res.message.length > 0) {
          this.detail = res.message[0]
          this.detailVisible = true
        } else {
          this.$message.warn('未查询到漏洞详情')
        }
      }).catch(() => {
        this.$message.error('漏洞详情获取失败')
      })
    },
    handleGenerateWord () {
      if (!this.currentTask) return
      this.generating = true
      this.$api.generate_word({ token: this.token, active_scan_id: this.currentTask.active_scan_id }).then(res => {
        this.generating = false
        if (res.code === 200) {
          const fileName = Array.isArray(res.message) ? res.message[0] : res.message
          if (!fileName) {
            this.$message.warn('报告生成成功但未返回文件名')
            return
          }
          this.$message.success('报告生成成功，开始下载')
          this.$api.download_word({ token: this.token, file_name: fileName }).then(downloadRes => {
            if (downloadRes && downloadRes.code === 403) this.$message.error('非法下载')
          }).catch(() => {})
        } else {
          this.$message.error(res.message || '报告生成失败')
        }
      }).catch(() => {
        this.generating = false
        this.$message.error('报告生成失败')
      })
    },
    rankColor (rank) {
      if (rank === '高危') return '#D32029'
      if (rank === '中危') return '#D89614'
      if (rank === '低危') return '#177DDC'
      return '#8C8C8C'
    },
    decodeB64 (val) {
      if (!val) return '(空)'
      try {
        return this.QJBase64Decode(val)
      } catch (e) {
        return String(val)
      }
    }
  }
}
</script>

<style lang="scss" scoped>
.site-info-page {
  padding: 12px;
  background: #141414;
  min-height: 100%;
}
.toolbar {
  display: flex;
  justify-content: space-between;
  margin-bottom: 8px;
}
.pack-pre {
  background: #141414;
  color: #BFBFBF;
  padding: 10px;
  border-radius: 4px;
  border: 1px solid #303030;
  font-size: 12px;
  line-height: 18px;
  max-height: 420px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-all;
  margin-bottom: 0;
}
::v-deep .row-selected > td {
  background: rgba(23, 125, 220, 0.15) !important;
}
::v-deep .ant-table {
  cursor: pointer;
}
::v-deep .ant-table-thead > tr > th {
  background: #1F1F1F;
  color: #BFBFBF;
  border-bottom: 1px solid #303030;
}
::v-deep .ant-table-tbody > tr > td {
  background: #141414;
  color: #BFBFBF;
  border-bottom: 1px solid #262626;
}
::v-deep .ant-descriptions-item-label {
  background: #1F1F1F !important;
}
::v-deep .ant-descriptions-item-content {
  color: #BFBFBF;
}
::v-deep .ant-tabs-tab {
  color: #8C8C8C;
}
::v-deep .ant-tabs-tab-active {
  color: #177DDC;
}
</style>
