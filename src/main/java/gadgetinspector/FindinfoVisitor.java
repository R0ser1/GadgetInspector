package gadgetinspector;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.InputStream;

public class FindinfoVisitor extends ClassVisitor {
    private String ower;
    public FindinfoVisitor(int api) {
        super(api);
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        this.ower=name;
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        if (this.ower.startsWith("com/mchange/v2/naming/ReferenceIndirector")){
            System.out.println(ower);
        }
        return super.visitMethod(access, name, descriptor, signature, exceptions);
    }
    public void discover(final ClassResourceEnumerator classResourceEnumerator) throws Exception {
        for (ClassResourceEnumerator.ClassResource classResource : classResourceEnumerator.getAllClasses()) {
            try (InputStream in = classResource.getInputStream()) {
                ClassReader cr = new ClassReader(in);
                try {
                    cr.accept(new FindinfoVisitor(Opcodes.ASM9), ClassReader.EXPAND_FRAMES);
                } catch (Exception e) {

                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
