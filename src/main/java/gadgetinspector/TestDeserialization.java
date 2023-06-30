package gadgetinspector;

import java.io.*;
import java.lang.reflect.Field;

public class TestDeserialization {

    interface Animal {
        public void eat();
    }

    public static class Cat implements Animal, Serializable {
        @Override
        public void eat() {
            System.out.println("cat eat fish");
        }
    }

    public static class Dog implements Animal, Serializable {
        @Override
        public void eat() {
            try {
                Runtime.getRuntime().exec("calc");
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.println("dog eat bone");
        }
    }

    public static class Person implements Serializable {
        private Animal pet = new Cat();

        private void readObject(java.io.ObjectInputStream stream)
                throws IOException, ClassNotFoundException {
            pet = (Animal) stream.readObject();
            pet.eat();
        }
    }

    public static void GeneratePayload(Object instance, String file)
            throws Exception {
        File f = new File(file);
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(f));
        out.writeObject(instance);
        out.flush();
        out.close();
    }

    public static void payloadTest(String file) throws Exception {
        ObjectInputStream in = new ObjectInputStream(new FileInputStream(file));
        Object obj = in.readObject();
        System.out.println(obj);
        in.close();
    }

    public static void main(String[] args) throws Exception {
        Animal animal = new Dog();
        Person person = new Person();
        Field field = person.getClass().getDeclaredField("pet");
        field.setAccessible(true);
        field.set(person, animal);

        GeneratePayload(person, "test.ser");
        payloadTest("test.ser");
    }
}