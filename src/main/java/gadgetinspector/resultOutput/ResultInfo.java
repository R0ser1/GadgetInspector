package gadgetinspector.resultOutput;

import gadgetinspector.GadgetChainDiscovery;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class ResultInfo {
    private String vulName;
    private String type;
    private List<String> links = new ArrayList<>();
    public void setLinks(List<String> links) {
        this.links = links;
    }

    public List<String> getLinks() {
        return links;
    }
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getVulName() {
        return vulName;
    }

    public void setVulName(String vulName) {
        this.vulName = vulName;
    }

    public List<String> getChains() {
        return links;
    }


    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.vulName);
        sb.append("\n");
        for (String s : links) {
            sb.append("\t");
            sb.append(s);
            sb.append("\n");
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ResultInfo that = (ResultInfo) o;
        boolean first = Objects.equals(vulName, that.vulName);
        boolean second = Objects.equals(type, that.type);
        boolean third = true;
        if (links.size() == that.links.size()) {
            for (int i = 0; i < links.size(); i++) {
                if (!links.get(i).equals(that.links.get(i))) {
                    third = false;
                    break;
                }
            }
            return first & second & third;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return Objects.hash(vulName, type, links);
    }
}
