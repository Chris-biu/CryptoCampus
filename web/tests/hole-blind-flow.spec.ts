import { mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

import BlindSignatureFlow from '@/views/hole/BlindSignatureFlow.vue'

describe('Issue #21 盲签名五步流程', () => {
  afterEach(() => vi.useRealTimers())

  it('展示五个协议步骤且不生成密码材料', () => {
    const wrapper = mount(BlindSignatureFlow)

    expect(wrapper.findAll('ol li')).toHaveLength(5)
    expect(wrapper.text()).toContain('M = SN ‖ service ‖ period')
    expect(wrapper.text()).toContain('不在浏览器中生成凭证、盲化因子或签名')
    expect(wrapper.text()).not.toContain('private_key')
    expect(wrapper.text()).not.toContain('session_key')
  })

  it('支持手动逐步回放与重置', async () => {
    const wrapper = mount(BlindSignatureFlow)

    await wrapper.get('.step-detail .el-button').trigger('click')
    expect(wrapper.get('[aria-current="step"]').text()).toContain('绑定业务上下文')

    const buttons = wrapper.findAll('.flow-actions .el-button')
    await buttons[0].trigger('click')
    expect(wrapper.get('[aria-current="step"]').text()).toContain('生成随机序列号')
  })

  it('自动播放抵达最后一步后停止', async () => {
    vi.useFakeTimers()
    const wrapper = mount(BlindSignatureFlow)

    const play = wrapper.findAll('.flow-actions .el-button')[1]
    await play.trigger('click')
    expect(wrapper.text()).toContain('暂停')

    await vi.advanceTimersByTimeAsync(5600)
    expect(wrapper.get('[aria-current="step"]').text()).toContain('去盲并一次性消费')
    expect(wrapper.text()).toContain('播放流程')
  })
})
