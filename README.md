针对GadgetInspector的一些思考，感谢前辈们的文章。让整个过程学起来变的轻松起来。这里作为记录防止自己以前写过的东西过快忘记，此文是几月后写的所以写的过于简陋。如看到可以看看文章推荐中的进行学习or看下简陋的源码。

## 文章

ASM学习(b站有视频教学)

```
https://lsieun.github.io/java/asm/index.html
```

一些学习过程中遇到的一些文章

```
https://paper.seebug.org/1281/
https://xz.aliyun.com/t/10756#toc-0 
https://xz.aliyun.com/t/7063
http://galaxylab.pingan.com.cn/java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E8%BE%85%E5%8A%A9%E5%B7%A5%E5%85%B7%E4%B9%8B-gadgetinspector/
https://github.com/4ra1n/code-inspector
https://pwnull.github.io/2023/Research-on-GadgetInspector-of-Static-Code-Scanning-Tool/
https://y4tacker.github.io/2022/05/09/year/2022/5/GadgetInspector%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90/#%E5%89%8D%E7%BD%AE%E5%BA%9F%E8%AF%9D
https://testbnull.medium.com/the-art-of-deserialization-gadget-hunting-part-3-how-i-found-cve-2020-2555-by-known-tools-67819b29cb63 
```

改进完的工具

```
https://github.com/5wimming/gadgetinspector
https://github.com/threedr3am/gadgetinspector
```

## 改进

工具是先自己改造，后来看了三梦师傅的框架，套用了很多再继续改进的。主要看了原作者以及5wimming师傅和threedr3am师傅的源码。通过上述文章进行学习。当然改进后续感觉也没太大进步，代码写的很烂。改进过程思想没设计好，后来直接放弃，这里简单记录下。

因为在此师傅们实现，所以尝试过一些源码，以及反序列化调用链的挖掘。分析为什么他们挖不出来，从而调试学习问题出在哪里。从而进行优化，下面是暂时记得的一些点。

先说一下实现的点，其中数组啥的用的state transitions思想，但是未精细化处理也很多bug。

1. 广度优先策略问题。
2. 实现父类中查找。
3. 数组 污点传递，对象 污点传递等问题(new )
4. 静态方法跟踪，导致污点移位误报问题
5. lamda 表达式简单实现。
6. spring支持
7. 新增source sink 以及污点传递
8. 类型转换问题。string.value等问题。

这里实现的点好几个是前辈们已经提出来 部分解决过了，所以这里主要说一下自己思考过的一些东西。

### 优化点3

数组污点传递，对象污点传递问题吧。主要是根据ASM 字节码执行的过程来的。类似于state transitions思想

再Callxxxxxxxx或者 Passthxxxxxxx中

![image-20230630140752529](https://lark-assets-prod-aliyun.oss-cn-hangzhou.aliyuncs.com/yuque/0/2023/png/22305987/1688107215479-c5f85d40-3946-44ff-b11f-f64db064f604.png)

例如数组是再字节码中执行的过程就是

```
ANEWARRAY
DUP
ICONST
ALOAD
AASTORE
```

在不同的visixxx中去记录这个状态 因为最终还是要在TaintTracking中实现的。所以这里记录状态就好了。

例如到visitInsn中当我们执行ANEARRAY我们就马上切换状态

![image-20230630141013033](https://lark-assets-prod-aliyun.oss-cn-hangzhou.aliyuncs.com/yuque/0/2023/png/22305987/1688107216236-6b1ca4da-d4b9-460e-ba95-b185245b9ee2.png)

从而一直记录即可实现。然后再最后执行到AASTORE我们可以调用TaiinTracking中写的方法

![image-20230630141106746](https://lark-assets-prod-aliyun.oss-cn-hangzhou.aliyuncs.com/yuque/0/2023/png/22305987/1688107216988-dcf091cc-acde-446d-9742-86df1e382932.png)

在这里我们对栈帧进行一个操作。通过控制从而让栈帧保持正确的污点传递。当然这并没有精细化处理。误报再所难免。

![image-20230630141130607](https://lark-assets-prod-aliyun.oss-cn-hangzhou.aliyuncs.com/yuque/0/2023/png/22305987/1688107217588-b98bc3f0-195a-4912-9970-3370c90d25e2.png)

### 其他优化点

类型转换 其实就是白名单增加，可以在源码查看。

ladmbda是在CallGrap中实现的，也是类似增加单独处理的机制。只能处理部分。

以及还有好一些优化吧，可以尝试看看源码。

## 总结

总结就是工具可玩性不高。但是作为一个ASM以及污点分析概念挺好。

源码