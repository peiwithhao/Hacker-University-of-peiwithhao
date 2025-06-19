# virtio
该技术用来实现半虚拟化
虚拟机的驱动程序和hypervisor的设备使用共享内存来进行交互,
使用特有的数据结构`virtioqueues`

```c
    /**
    * struct virtqueue - a queue to register buffers for sending or receiving.
    * @list: the chain of virtqueues for this device
    * @callback: the function to call when buffers are consumed (can be NULL).
    * @name: the name of this virtqueue (mainly for debugging)
    * @vdev: the virtio device this queue was created for.
    * @priv: a pointer for the virtqueue implementation to use.
    * @index: the zero-based ordinal number for this queue.
    * @num_free: number of elements we expect to be able to fit.
    * @num_max: the maximum number of elements supported by the device.
    * @reset: vq is in reset state or not.
    *
    * A note on @num_free: with indirect buffers, each buffer needs one
    * element in the queue, otherwise a buffer will need one element per
    * sg element.
    */
    struct virtqueue {
        struct list_head list;
        void (*callback)(struct virtqueue *vq);
        const char *name;
        struct virtio_device *vdev;
        unsigned int index;
        unsigned int num_free;
        unsigned int num_max;
        void *priv;
        bool reset;
    };
```

# 参考
[virtio on linux kernel documentation](https://docs.kernel.org/driver-api/virtio/virtio.htmlrl)  

