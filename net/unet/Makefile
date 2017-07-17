#
# Makefile for the Linux uNet layer
#

obj-$(CONFIG_UNET) := unet.o

unet-y += core.o bearer.o eth_media.o socket.o \
	  proc.o configfs.o packet.o fsm.o sysfs.o \
	  utils.o crypto.o router.o next_hop.o conn.o \
	  app.o dev.o
