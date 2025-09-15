package utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SimpleBenchmark {

    /**
     * 计算一个函数多次执行的平均耗时（去掉一个最高值和一个最低值）。
     *
     * @param count 执行次数，必须为3次或以上。
     * @param task  要执行的函数 (Runnable)。
     * @return 平均耗时（单位：毫秒 ms）。
     */
    public static double getAverageTime(int count, Runnable task) {
        List<Long> timings = new ArrayList<>();

        // 1. 多次执行并记录耗时
        for (int i = 0; i < count; i++) {
            long startTime = System.nanoTime();
            task.run();
            timings.add(System.nanoTime() - startTime);
        }
        System.out.println(task.toString());
        // 2. 排序并移除首尾两个极端值
        Collections.sort(timings);
        System.out.println(timings);

        timings.remove(0); // 移除最低
        timings.remove(timings.size() - 1); // 移除最高
        // 3. 计算剩余部分的平均值
        double averageNanos = timings.stream()
                .mapToLong(Long::longValue)
                .average()
                .orElse(0.0);

        // 4. 将纳秒(ns)转换为毫秒(ms)并返回
        return averageNanos / 1_000_000.0;
    }

    // ================== 使用示例 ==================
    public static void main(String[] args) {

        // 定义一个要测试的任务
        Runnable myTask = () -> {
            // 假设这里是你要测试性能的代码
            int sum = 0;
            for (int i = 0; i < 10000; i++) {
                sum += i;
            }
        };

        // 调用函数，执行20次
        double avgTime = getAverageTime(20, myTask);

        // 打印结果
        System.out.printf("（去掉最高和最低后）平均执行耗时: %.6f ms\n", avgTime);
    }
}