package utils;

import java.util.Objects;

/**
 * 泛型键值对容器，可存储两个不同类型的值.
 * @param <K> 第一个元素的类型
 * @param <V> 第二个元素的类型
 */
public class Pair<K, V> {
    private final K first;
    private final V second;

    // 私有构造方法，强制使用工厂方法 of()
    private Pair(K first, V second) {
        this.first = first;
        this.second = second;
    }

    /**
     * 创建 Pair 实例
     * @param first  第一个元素
     * @param second 第二个元素
     * @return 新的 Pair 实例
     */
    public static <K, V> Pair<K, V> of(K first, V second) {
        return new Pair<>(first, second);
    }

    public K getFirst() {
        return first;
    }

    public V getSecond() {
        return second;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Pair<?, ?> pair = (Pair<?, ?>) o;
        return Objects.equals(first, pair.first) &&
                Objects.equals(second, pair.second);
    }

    @Override
    public int hashCode() {
        return Objects.hash(first, second);
    }

    @Override
    public String toString() {
        return "(" + first + ", " + second + ")";
    }
}