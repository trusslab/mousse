#include <target-arm/cpu.h>
#include <assert.h>

void armv7m_nvic_set_pending(void *opaque, int irq) {
	assert(false && "armv7m_nvic_set_pending failed\n");
}
int armv7m_nvic_acknowledge_irq(void *opaque) {
	assert(false && "armv7m_nvic_acknowledge_irq failed\n");
}
void armv7m_nvic_complete_irq(void *opaque, int irq) {
	assert(false && "armv7m_nvic_complete_irq failed\n");
}
