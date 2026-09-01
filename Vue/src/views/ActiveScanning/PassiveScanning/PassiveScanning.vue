<template>
  <a-row type="flex" justify="center" style="height:100%;min-height: 540px;text-align:left" :gutter="[16, { xs: 4, sm: 8, md: 12, lg: 16 }]">
    <a-col :xs="{ span: 24 }" :lg="{ span: 8 }">
      <Card name="创建被动扫描项目">
        <div style="font-size: 14px; color: #8c8c8c;margin-bottom: 14px;">创建代理扫描项目，将浏览器/客户端代理指向下方代理地址后，流量将被留存并做被动检测。</div>
        <a-form :form="ProjectForm" layout="vertical">
          <a-form-item label="项目名称：">
            <a-input v-decorator="['proxy_project_name', { rules: [{ required: true, message: '请输入项目名称' }] }]" placeholder="例如：内网资产流量审计"></a-input>
          </a-form-item>
          <a-form-item label="代理账号：">
            <a-input v-decorator="['proxy_username', { rules: [{ required: true, message: '请输入代理账号' }] }]" placeholder="用于代理认证的账号"></a-input>
          </a-form-item>
          <a-form-item label="代理密码：">
            <a-input-password v-decorator="['proxy_password', { rules: [{ required: true, message: '请输入代理密码' }] }]" placeholder="用于代理认证的密码"></a-input-password>
          </a-form-item>
          <a-form-item label="有效期至：">
            <a-date-picker
              v-decorator="['end_time', { rules: [{ required: true, message: '请选择有效期' }] }]"
              style="width: 100%"
              show-time
              placeholder="选择项目到期时间"
            ></a-date-picker>
          </a-form-item>
        </a-form>
        <div style="text-align: center;margin-top: 10px;">
          <a-button type="primary" :loading="createLoading" @click="handleCreate">创建项目</a-button>
        </div>
      </Card>
    </a-col>
    <a-col :xs="{ span: 24 }" :lg="{ span: 16 }">
      <Card name="项目列表">
        <template slot="extraCard">
          <a-button type="link" icon="reload" @click="handleQuery">刷新</a-button>
        </template>
        <a-table
          :columns="columns"
          :data-source="projectList"
          :pagination="{ pageSize: 8 }"
          row-key="proxy_id"
          size="middle"
          :loading="listLoading"
        >
          <template slot="status" slot-scope="text">
            <a-tag :color="text == '1' ? 'green' : 'red'">{{ text == '1' ? '运行中' : '已停止' }}</a-tag>
          </template>
          <template slot="creation_time" slot-scope="text">
            {{ moment(text * 1000).format('YYYY-MM-DD HH:mm:ss') }}
          </template>
          <template slot="end_time" slot-scope="text">
            {{ text && text != '0' ? moment(text * 1000).format('YYYY-MM-DD HH:mm:ss') : '永久' }}
          </template>
          <template slot="action" slot-scope="text, record">
            <a-button type="link" size="small" icon="eye" @click="handleQueryData(record)">流量</a-button>
            <a-button v-if="record.status == '0'" type="link" size="small" icon="play-circle" @click="handleUpdateStatus(record, '1')">启动</a-button>
            <a-button v-else type="link" size="small" icon="pause-circle" @click="handleUpdateStatus(record, '0')">停止</a-button>
            <a-button type="link" size="small" icon="delete" style="color: #d32029" @click="handleDelete(record)">删除</a-button>
          </template>
        </a-table>
      </Card>
    </a-col>

    <a-col :span="24">
      <Card name="代理连接指引" :show-title="true">
        <a-alert type="info" show-icon :message="'代理地址：' + proxyAddress" description="将浏览器或客户端的 HTTP/HTTPS 代理指向上述地址，并在弹窗中填写项目创建时设置的代理账号与密码，即可开始抓取流量。抓取到的数据会显示在下方流量明细中。" />
      </Card>
    </a-col>

    <a-col :span="24">
      <Card name="流量明细">
        <a-table
          :columns="dataColumns"
          :data-source="trafficList"
          :pagination="{ pageSize: 8 }"
          row-key="original_proxy_id"
          size="middle"
          :loading="dataLoading"
        >
          <template slot="creation_time" slot-scope="text">
            {{ moment(text * 1000).format('YYYY-MM-DD HH:mm:ss') }}
          </template>
          <template slot="issue_task_status" slot-scope="text">
            <a-tag :color="text == '1' ? 'green' : 'orange'">{{ text == '1' ? '已检测' : '待检测' }}</a-tag>
          </template>
        </a-table>
      </Card>
    </a-col>
  </a-row>
</template>

<script>
import { mapGetters } from 'vuex'
import Card from '@/components/Card/Card.vue'
import { OverallMixins } from '@/js/Mixins/OverallMixins.js'

export default {
  name: 'PassiveScanning',
  mixins: [OverallMixins],
  components: { Card },
  data () {
    return {
      ProjectForm: this.$form.createForm(this, { name: 'ProjectForm' }),
      createLoading: false,
      listLoading: false,
      dataLoading: false,
      projectList: [],
      trafficList: [],
      currentProxyId: '',
      proxyAddress: window.location.host + ' (HTTP/HTTPS 代理端口 8889)',
      columns: [
        { title: '项目名称', dataIndex: 'proxy_project_name', key: 'proxy_project_name' },
        { title: '代理账号', dataIndex: 'proxy_username', key: 'proxy_username' },
        { title: '项目ID', dataIndex: 'proxy_id', key: 'proxy_id' },
        { title: '状态', dataIndex: 'status', key: 'status', scopedSlots: { customRender: 'status' }, width: 90 },
        { title: '创建时间', dataIndex: 'creation_time', key: 'creation_time', scopedSlots: { customRender: 'creation_time' } },
        { title: '到期时间', dataIndex: 'end_time', key: 'end_time', scopedSlots: { customRender: 'end_time' } },
        { title: '操作', dataIndex: 'action', key: 'action', scopedSlots: { customRender: 'action' }, width: 190 }
      ],
      dataColumns: [
        { title: 'ID', dataIndex: 'original_proxy_id', key: 'original_proxy_id', width: 80 },
        { title: '请求方法', dataIndex: 'request_method', key: 'request_method', width: 110 },
        { title: 'URL', dataIndex: 'url', key: 'url' },
        { title: '状态码', dataIndex: 'response_status_code', key: 'response_status_code', width: 90 },
        { title: '检测状态', dataIndex: 'issue_task_status', key: 'issue_task_status', scopedSlots: { customRender: 'issue_task_status' }, width: 100 },
        { title: '抓取时间', dataIndex: 'creation_time', key: 'creation_time', scopedSlots: { customRender: 'creation_time' }, width: 170 }
      ]
    }
  },
  computed: {
    ...mapGetters({
      token: "UserStore/token"
    })
  },
  mounted () {
    this.handleQuery()
  },
  methods: {
    handleCreate () { // 创建被动扫描项目
      this.ProjectForm.validateFields((err, values) => {
        if (err) return
        this.createLoading = true
        const params = {
          token: this.token,
          proxy_project_name: values.proxy_project_name,
          proxy_username: values.proxy_username,
          proxy_password: values.proxy_password,
          end_time: String(Math.round(values.end_time.valueOf() / 1000))
        }
        this.$api.create_proxy_scan_project(params).then((res) => {
          this.createLoading = false
          if (res.code == 200) {
            this.$message.success(res.message)
            this.ProjectForm.resetFields()
            this.handleQuery()
          } else {
            this.$message.error(res.message)
          }
        }).catch(() => {
          this.createLoading = false
        })
      })
    },
    handleQuery () { // 查询项目列表
      this.listLoading = true
      const params = { token: this.token }
      this.$api.query_proxy_scan_project(params).then((res) => {
        this.listLoading = false
        if (res.code == 200) {
          this.projectList = res.message || []
        } else {
          this.$message.error(res.message)
        }
      }).catch(() => {
        this.listLoading = false
      })
    },
    handleUpdateStatus (record, status) { // 启停项目
      const params = {
        token: this.token,
        proxy_id: record.proxy_id,
        status: status
      }
      this.$api.update_proxy_scan_project_status(params).then((res) => {
        if (res.code == 200) {
          this.$message.success(res.message)
          this.handleQuery()
        } else {
          this.$message.error(res.message)
        }
      })
    },
    handleDelete (record) { // 删除项目
      const self = this
      this.$confirm({
        title: '确定要删除该项目吗？',
        content: `项目「${record.proxy_project_name}」删除后其抓取数据将一并移除，请谨慎操作。`,
        okText: '删除',
        okType: 'danger',
        cancelText: '取消',
        onOk () {
          const params = { token: self.token, proxy_id: record.proxy_id }
          return self.$api.delete_proxy_scan_project(params).then((res) => {
            if (res.code == 200) {
              self.$message.success(res.message)
              self.handleQuery()
              if (self.currentProxyId == record.proxy_id) {
                self.trafficList = []
                self.currentProxyId = ''
              }
            } else {
              self.$message.error(res.message)
            }
          })
        }
      })
    },
    handleQueryData (record) { // 查询项目流量明细
      this.dataLoading = true
      this.currentProxyId = record.proxy_id
      const params = { token: this.token, proxy_id: record.proxy_id }
      this.$api.query_proxy_scan_data(params).then((res) => {
        this.dataLoading = false
        if (res.code == 200) {
          this.trafficList = res.message || []
          if (this.trafficList.length == 0) {
            this.$message.info('该项目暂无抓取流量')
          }
        } else {
          this.$message.error(res.message)
        }
      }).catch(() => {
        this.dataLoading = false
      })
    }
  }
}
</script>

<style lang="less" scoped>
</style>
