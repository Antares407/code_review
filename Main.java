package newcoder.Y2021.MT.C10;

import java.util.Arrays;
import java.util.Scanner;

/**
 * 美团2021校招笔试-编程题(通用编程试题,第10场)

 1.
淘汰分数
某比赛已经进入了淘汰赛阶段,已知共有n名选手参与了此阶段比赛，他们的得分分别是a_1,a_2….a_n,小美作为比赛的裁判希望设定一个分数线m，使得所有分数大于m的选手晋级，其他人淘汰。

但是为了保护粉丝脆弱的心脏，小美希望晋级和淘汰的人数均在[x,y]之间。

显然这个m有可能是不存在的，也有可能存在多个m，如果不存在，请你输出-1，如果存在多个，请你输出符合条件的最低的分数线。
 */
public class Main {
    public static void main(String[] args) {
        Scanner in = new Scanner(System.in);

        //n是选手个数，[x,y]是晋级和淘汰区间
        int n = in.nextInt();
        int x = in.nextInt();
        int y = in.nextInt();

        int[] scores = new int[n+1];
        for (int i = 1; i < n+1; i++) {
            scores[i] = in.nextInt();
        }
        Arrays.sort(scores);
        //划分的区间
        int startIndex = Math.max(x, n-y);//包含
        int endIndex = Math.min(y, n-x);//包含

        if(startIndex > endIndex) System.out.println(-1);
        else System.out.println(scores[startIndex]);
    }
}
