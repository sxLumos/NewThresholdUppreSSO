package utils;

import java.math.BigInteger;

public class Lagrange {

    /**
     * 计算拉格朗日基多项式在点 0 的值 (lambda_i)
     * lambda_i = product_{j in S, j!=i} (j / (j-i)) mod m
     *
     * @param i      当前服务器的索引
     * @param serverIndices 参与计算的服务器索引集合 SE
     * @param mod    模数 m (群的阶)
     * @return lambda_i
     */
    public static BigInteger getCoefficient(int i, int[] serverIndices, BigInteger mod) {
        BigInteger xi = BigInteger.valueOf(i);
        BigInteger numerator = BigInteger.ONE;
        BigInteger denominator = BigInteger.ONE;

        for (int j : serverIndices) {
            if (i == j) {
                continue;
            }
            BigInteger xj = BigInteger.valueOf(j);
            // Numerator: product(xj)
            numerator = numerator.multiply(xj).mod(mod);
            // Denominator: product(xj - xi)
            denominator = denominator.multiply(xj.subtract(xi)).mod(mod);
        }

        // lambda_i = numerator * modInverse(denominator)
        return numerator.multiply(denominator.modInverse(mod)).mod(mod);
    }
}