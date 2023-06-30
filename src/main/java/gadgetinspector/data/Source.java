package gadgetinspector.data;

import java.util.Objects;

public class Source {
    private final MethodReference.Handle sourceMethod;
    private final int taintedArgIndex;

    public Source(MethodReference.Handle sourceMethod,int taintedArgIndex) {
        this.sourceMethod = sourceMethod;
        this.taintedArgIndex = taintedArgIndex;
    }

    public MethodReference.Handle getSourceMethod() {
        return sourceMethod;
    }

    public int getTaintedArgIndex() {
        return taintedArgIndex;
    }

    public static class Factory implements DataFactory<Source> {

        @Override
        public Source parse(String[] fields) {
            return new Source(
                    new MethodReference.Handle(new ClassReference.Handle(fields[0]), fields[1], fields[2]),
                    Integer.parseInt(fields[3])
            );
        }

        @Override
        public String[] serialize(Source obj) {
            return new String[]{
                    obj.sourceMethod.getClassReference().getName(), obj.sourceMethod.getName(), obj.sourceMethod.getDesc(),
                    Integer.toString(obj.taintedArgIndex),
            };
        }
    }
    @Override
    public int hashCode() {
        return Objects.hash(sourceMethod, taintedArgIndex);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Source source = (Source) o;
        return taintedArgIndex == source.taintedArgIndex &&
                Objects.equals(sourceMethod, source.sourceMethod);
    }

}
