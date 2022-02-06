package cic.cs.unb.ca.jnetpcap;

public enum ProtocolEnum {

    TCP(6),
    UDP(17),
    DEFAULT(0);

    public final int val;

    private ProtocolEnum(int num) {
        this.val = num;
    }
}
