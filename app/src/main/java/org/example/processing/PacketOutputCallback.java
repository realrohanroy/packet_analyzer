package org.example.processing;

import org.example.core.Types.PacketJob;
import org.example.core.Types.PacketAction;

public interface PacketOutputCallback {

    void handle(PacketJob job, PacketAction action);

}
